/// Transfer thread
use std::mem;
use std::time::{self,Duration};
use std::thread;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use ::netmap::{self, NetmapDescriptor, TxSlot, NetmapSlot};
use ::OutgoingPacket;
use ::packet;
use ::scheduler;
use ::scheduler::{CpuSet, Policy};
use ::pnet::util::MacAddr;
use ::pnet::packet::ethernet::MutableEthernetPacket;
use ::spsc;
use ::util;
use ::metrics;

#[derive(Debug,Default)]
struct TxStats {
    pub sent: u32,
    pub failed: u32,
}

impl TxStats {
    pub fn empty() -> Self {
        Default::default()
    }

    pub fn clear(&mut self) {
        *self = Default::default();
    }

    pub fn make_metrics<'a>(&self, seconds: u32) -> [metrics::Metric<'a>;2] {
        use metrics::Metric;
        [
            Metric::new("tx_pps", (self.sent / seconds) as i64),
            Metric::new("tx_failed", (self.failed / seconds) as i64),
        ]
    }
}

pub struct Sender<'a> {
    ring_num: u16,
    cpu: usize,
    chan: spsc::Consumer<OutgoingPacket>,
    netmap: &'a mut NetmapDescriptor,
    lock: Arc<AtomicUsize>,
    source_mac: MacAddr,
    stats: TxStats,
    metrics_addr: &'a str,
}

impl<'a> Sender<'a> {
    pub fn new(ring_num: u16, cpu: usize,
               chan: spsc::Consumer<OutgoingPacket>,
               netmap: &'a mut NetmapDescriptor,
               lock: Arc<AtomicUsize>,
               source_mac: MacAddr,
               metrics_addr: &'a str) -> Sender<'a> {
        Sender {
            ring_num: ring_num,
            cpu: cpu,
            chan: chan,
            netmap: netmap,
            lock: lock,
            source_mac: source_mac,
            stats: TxStats::empty(),
            metrics_addr: metrics_addr,
        }
    }

    fn send_metrics(client: &metrics::Client, stats: &TxStats, seconds: u32) {
        let metrics = stats.make_metrics(seconds);
        &(*client).send(&metrics);
    }

    // main transfer loop
    pub fn run(mut self) {
        info!("TX loop for ring {:?} starting. Rings: {:?}", self.ring_num, self.netmap.get_tx_rings());
        let metrics_client = metrics::Client::new(self.metrics_addr);

        util::set_thread_name(&format!("syncookied/tx{:02}", self.ring_num));

        scheduler::set_self_affinity(CpuSet::single(self.cpu)).expect("setting affinity failed");
        scheduler::set_self_policy(Policy::Fifo, 20).expect("setting sched policy failed");

        /* wait for card to reinitialize */
        thread::sleep(Duration::new(1, self.ring_num as u32 * 100));
        info!("[TX#{}] started", self.ring_num);

        let mut before = time::Instant::now();
        let seconds: u32 = 5;
        let ival = time::Duration::new(seconds as u64, 0);
        let mut rate: u32 = 0;

        self.update_routing_cache();

        loop {
            /* block and wait for packet in queue */
            if let Some(_) = self.netmap.poll(netmap::Direction::Output) {
                if let Some(ring) = self.netmap.tx_iter().next() {
                    let mut tx_iter = ring.iter();

                    /* send one packet */
                    if let Some((slot, buf)) = tx_iter.next() {
                        let stats = &mut self.stats;
                        let lock = &mut self.lock;
                        let ring_num = self.ring_num;
                        let source_mac = self.source_mac;
                        match self.chan.try_pop_with(|pkt| {
                            if rate < 1000 {
                                ::RoutingTable::sync_tables();
                            }
                            Self::send(pkt, slot, buf, stats, lock,
                                       ring_num, source_mac);
                        }) {
                            None => thread::sleep(Duration::new(0, 100)),
                            Some(_) => { },
                        }
                    }
                    /* try to send more if we have any (non-blocking) */
                    for (slot, buf) in tx_iter {
                        let stats = &mut self.stats;
                        let lock = &mut self.lock;
                        let ring_num = self.ring_num;
                        let source_mac = self.source_mac;
                        match self.chan.try_pop_with(|pkt| {
                                Self::send(pkt, slot, buf, stats, lock,
                                           ring_num, source_mac);
                        }) {
                            None => thread::sleep(Duration::new(0, 200)),
                            Some(_) => { },
                        }
/*
                        if rate <= 1000 {
                            break; // do tx sync on every packet if we receive
                            // small amount of packets
                        } else if rate <= 10_000 && self.stats.sent % 64 == 0 {
                            break;
                        } else if rate <= 100_000 && self.stats.sent % 128 == 0 {
                            break;
                        }
*/
                    }
                }
            }
            if before.elapsed() >= ival {
                Self::send_metrics(&metrics_client, &self.stats, seconds);
                rate = self.stats.sent/seconds;
                info!("[TX#{}]: sent {}Pkts/s, failed {}Pkts/s", self.ring_num, rate, self.stats.failed/seconds);
                self.stats.clear();
                before = time::Instant::now();
                self.update_routing_cache();
            }
        }
    }

    fn update_routing_cache(&mut self) {
        ::RoutingTable::sync_tables();
    }

    #[inline]
    fn send(pkt: &OutgoingPacket, slot: &mut TxSlot, buf: &mut [u8], stats: &mut TxStats,
            lock: &mut Arc<AtomicUsize>, _ring_num: u16, source_mac: MacAddr) {
        match pkt {
            &OutgoingPacket::Ingress(ref pkt) => {
                if let Some(len) = packet::handle_reply(&pkt, source_mac, buf) {
                    //debug!("[TX#{}] SENDING PACKET\n", ring_num);
                    slot.set_flags(0); //netmap::NS_BUF_CHANGED as u16 /* | netmap::NS_REPORT as u16 */);
                    slot.set_len(len as u16);
                    stats.sent += 1;
                } else {
                    stats.failed += 1;
                }
            },
            &OutgoingPacket::Forwarded((slot_ptr, buf_ptr, destination_mac)) => {
                use std::slice;
                /* swap buffers (zero copy) */
                let rx_slot: &mut TxSlot = unsafe { mem::transmute(slot_ptr as *mut TxSlot) };
                let tx_idx = slot.get_buf_idx();
                let tx_len = slot.get_len();

                slot.set_buf_idx(rx_slot.get_buf_idx());
                slot.set_len(rx_slot.get_len());
                slot.set_flags(netmap::NS_BUF_CHANGED);

                rx_slot.set_buf_idx(tx_idx);
                rx_slot.set_len(tx_len);
                rx_slot.set_flags(netmap::NS_BUF_CHANGED as u16);

                let to_forward = &lock;
                to_forward.fetch_sub(1, Ordering::SeqCst);
                
                let mut buf = unsafe { slice::from_raw_parts_mut::<u8>(buf_ptr as *mut u8, slot.get_len() as usize) };
    /*
                {
                    packet::dump_input(&buf);
                    debug!("[TX#{}]: received slot: {:x} buf: {:x}, buf_idx: {} (was buf_idx: {})",
                        ring_num, slot_ptr, buf_ptr, slot.get_buf_idx(), tx_idx);
                }
    */
                {
                    let mut eth = MutableEthernetPacket::new(&mut buf[0..]).unwrap();
                    eth.set_source(source_mac);
                    eth.set_destination(destination_mac);
                }
                stats.sent += 1;
            }
        }
    }
}
