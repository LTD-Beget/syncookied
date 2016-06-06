use std::mem;
use std::time::{self,Duration};
use std::thread;
use ::mpsc;
use ::mpsc::TryRecvError;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use ::netmap::{self, NetmapDescriptor, TxSlot, NetmapSlot};
use ::OutgoingPacket;
use ::packet;
use ::scheduler;
use ::scheduler::{CpuSet, Policy};
use ::pnet::util::MacAddr;
use ::pnet::packet::ethernet::MutableEthernetPacket;
use ::util;

#[derive(Debug,Default)]
struct TxStats {
    pub sent: usize,
    pub failed: usize,
}

impl TxStats {
    pub fn empty() -> Self {
        Default::default()
    }

    pub fn clear(&mut self) {
        *self = Default::default();
    }
}

pub struct Sender<'a> {
    ring_num: u16,
    cpu: usize,
    chan: mpsc::Receiver<OutgoingPacket>,
    netmap: &'a mut NetmapDescriptor,
    lock: Arc<AtomicUsize>,
    source_mac: MacAddr,
    stats: TxStats,
}

impl<'a> Sender<'a> {
    pub fn new(ring_num: u16, cpu: usize, chan: mpsc::Receiver<OutgoingPacket>,
            netmap: &'a mut NetmapDescriptor, lock: Arc<AtomicUsize>,
            source_mac: MacAddr) -> Sender<'a> {
        Sender {
            ring_num: ring_num,
            cpu: cpu,
            chan: chan,
            netmap: netmap,
            lock: lock,
            source_mac: source_mac,
            stats: TxStats::empty(),
        }
    }

    pub fn run(mut self) {
        println!("TX loop for ring {:?} starting. Rings: {:?}", self.ring_num, self.netmap.get_tx_rings());

        util::set_thread_name(&format!("syncookied/tx{:02}", self.ring_num));

        scheduler::set_self_affinity(CpuSet::single(self.cpu)).expect("setting affinity failed");
        scheduler::set_self_policy(Policy::Fifo, 20).expect("setting sched policy failed");

        /* wait for card to reinitialize */
        thread::sleep(Duration::new(1, 0));
        println!("[TX#{}] started", self.ring_num);

        let mut before = time::Instant::now();
        let seconds: usize = 5;
        let ival = time::Duration::new(seconds as u64, 0);
        let mut rate: usize = 0;

        self.update_routing_cache();

        loop {
            //let fd = netmap.get_fd();
            /* block and wait for packet in queue */
            if let Some(_) = self.netmap.poll(netmap::Direction::Output) {
                if let Some(ring) = self.netmap.tx_iter().next() {
                    let mut tx_iter = ring.iter();

                    /* send one packet */
                    if let Some((slot, buf)) = tx_iter.next() {
                        let pkt = self.chan.recv().expect("Expected RX not to die on us");
                        if rate < 1000 {
                            ::RoutingTable::sync_tables();
                        }
                        Self::send(pkt, slot, buf, &mut self.stats, &mut self.lock,
                                   self.ring_num, self.source_mac);

                    }
                    /* try to send more if we have any (non-blocking) */
                    for (slot, buf) in tx_iter {
                        match self.chan.try_recv() {
                            Ok(pkt) => Self::send(pkt, slot, buf, &mut self.stats, &mut self.lock,
                                                  self.ring_num, self.source_mac),
                            Err(TryRecvError::Empty) => break,
                            Err(TryRecvError::Disconnected) => panic!("Expected RX not to die on us"),
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
                rate = self.stats.sent/seconds;
                println!("[TX#{}]: sent {}Pkts/s, failed {}Pkts/s", self.ring_num, rate, self.stats.failed/seconds);
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
    fn send(pkt: OutgoingPacket, slot: &mut TxSlot, buf: &mut [u8], stats: &mut TxStats,
            lock: &mut Arc<AtomicUsize>, ring_num: u16, source_mac: MacAddr) {
        match pkt {
            OutgoingPacket::Ingress(pkt) => {
                if let Some(len) = packet::handle_reply(pkt, source_mac, buf) {
                    //println!("[TX#{}] SENDING PACKET\n", ring_num);
                    slot.set_flags(0); //netmap::NS_BUF_CHANGED as u16 /* | netmap::NS_REPORT as u16 */);
                    slot.set_len(len as u16);
                    stats.sent += 1;
                } else {
                    stats.failed += 1;
                }
            },
            OutgoingPacket::Forwarded((slot_ptr, buf_ptr, destination_mac)) => {
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
                    println!("[TX#{}]: received slot: {:x} buf: {:x}, buf_idx: {} (was buf_idx: {})",
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
