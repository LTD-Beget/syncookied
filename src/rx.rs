/// Receiver thread
use std::time::{self,Duration};
use std::thread;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use ::netmap::{self, NetmapDescriptor, RxSlot};
use ::ForwardedPacket;
use ::packet::{self,IngressPacket};
use ::scheduler;
use ::scheduler::{CpuSet, Policy};
use ::pnet::util::MacAddr;
use ::util;
use ::libc;
use ::spsc;
use ::packet::Action;
use ::metrics;

#[derive(Debug,Default)]
struct RxStats {
    pub received: u32,
    pub dropped: u32,
    pub forwarded: u32,
    pub queued: u32,
    pub overflow: u32,
    pub failed: u32,
}

impl RxStats {
    pub fn empty() -> Self {
        Default::default()
    }

    pub fn clear(&mut self) {
        *self = Default::default();
    }

}

pub struct Receiver<'a> {
    cpu: usize,
    chan_reply: spsc::Producer<IngressPacket>,
    chan_fwd: spsc::Producer<ForwardedPacket>,
    netmap: &'a mut NetmapDescriptor,
    stats: RxStats,
    lock: Arc<AtomicUsize>,
    mac: MacAddr,
    ring_num: u16,
    metrics_addr: Option<&'a str>,
}

#[inline(always)]
fn adaptive_push<T>(chan: &spsc::Producer<T>, pkt: T, retries: usize) -> Option<T> {
    // fast path
    let mut packet = pkt;
    for _ in 0..retries - 1 {
        if let Some(pkt) = chan.try_push(packet) {
            packet = pkt;
            unsafe { libc::sched_yield() };
        } else {
            return None;
        }
    }
    // no luck
    chan.try_push(packet)
}


impl<'a> Receiver<'a> {
    pub fn new(ring_num: u16, cpu: usize,
               chan_fwd: spsc::Producer<ForwardedPacket>,
               chan_reply: spsc::Producer<IngressPacket>,
               netmap: &'a mut NetmapDescriptor,
               lock: Arc<AtomicUsize>,
               mac: MacAddr,
               metrics_addr: Option<&'a str>) -> Self {
        Receiver {
            ring_num: ring_num,
            cpu: cpu,
            chan_fwd: chan_fwd,
            chan_reply: chan_reply,
            netmap: netmap,
            lock: lock,
            stats: RxStats::empty(),
            mac: mac,
            metrics_addr: metrics_addr,
        }
    }

    fn update_routing_cache(&mut self) {
        ::RoutingTable::sync_tables();
    }

    fn make_metrics<'t>(tags: &'t [(&'t str, &'t str)]) -> [metrics::Metric<'t>;6] {
        use metrics::Metric;
        [
            Metric::new_with_tags("rx_pps", tags),
            Metric::new_with_tags("rx_drop", tags),
            Metric::new_with_tags("rx_forwarded", tags),
            Metric::new_with_tags("rx_queued", tags),
            Metric::new_with_tags("rx_overflow", tags),
            Metric::new_with_tags("rx_failed", tags),
        ]
    }

    fn update_metrics<'t>(stats: &'t RxStats, metrics: &mut [metrics::Metric<'a>;6], seconds: u32) {
        metrics[0].set_value((stats.received / seconds) as i64);
        metrics[1].set_value((stats.dropped / seconds) as i64);
        metrics[2].set_value((stats.forwarded / seconds) as i64);
        metrics[3].set_value((stats.queued / seconds) as i64);
        metrics[4].set_value((stats.overflow / seconds) as i64);
        metrics[5].set_value((stats.failed / seconds) as i64);
    }

    // main RX loop
    pub fn run(mut self) {
        let metrics_client = self.metrics_addr.map(metrics::Client::new);
        let hostname = util::get_host_name().unwrap();
        let queue = format!("{}", self.ring_num);
        let ifname = self.netmap.get_ifname();
        let tags = [("queue", queue.as_str()), ("host", hostname.as_str()), ("iface", ifname.as_str())];
        let mut metrics = Self::make_metrics(&tags[..]);

        info!("RX loop for ring {:?}", self.ring_num);
        info!("Rx rings: {:?}", self.netmap.get_rx_rings());
        util::set_thread_name(&format!("syncookied/rx{:02}", self.ring_num));

        scheduler::set_self_affinity(CpuSet::single(self.cpu)).expect("setting affinity failed");
        scheduler::set_self_policy(Policy::Fifo, 20).expect("setting sched policy failed");

        /* wait for card to reinitialize */
        thread::sleep(Duration::new(1, self.ring_num as u32 * 100));
        info!("[RX#{}] started", self.ring_num);

        self.update_routing_cache();

        let mut before = time::Instant::now();
        let seconds: u32 = 5;
        let mut rate: u32 = 0;
        let ival = time::Duration::new(seconds as u64, 0);

        loop {
            if let Some(_) = self.netmap.poll(netmap::Direction::Input) {
                if let Some(ring) = self.netmap.rx_iter().next() {
                    let mut fw = false;
                    for (slot, buf) in ring.iter() {
                        self.stats.received += 1;
                        if rate < 1000 {
                            ::RoutingTable::sync_tables();
                        }
                        match packet::handle_input(buf, self.mac) {
                            Action::Drop => {
                                self.stats.dropped += 1;
                            },
                            Action::Forward(fwd_mac) => {
                                let to_forward = &self.lock;

                                let slot_ptr: usize = slot as *mut RxSlot as usize;
                                let buf_ptr: usize = buf.as_ptr() as usize;

/*
                                println!("[RX#{}]: forwarded slot: {:x} buf: {:x}, buf_idx: {}",
                                    ring_num, slot_ptr, buf_ptr, slot.get_buf_idx());
*/
                                to_forward.fetch_add(1, Ordering::SeqCst);
                                let chan = &self.chan_fwd;
                                let packet = ForwardedPacket {
                                    slot_ptr: slot_ptr,
                                    buf_ptr: buf_ptr,
                                    destination_mac: fwd_mac,
                                };
                                match adaptive_push(chan, packet, 1) {
                                    Some(_) => self.stats.failed += 1,
                                    None => {
                                        self.stats.forwarded += 1;
                                        fw = true;
                                    },
                                }
                            },
                            Action::Reply(packet) => {
                                match self.chan_reply.try_push(packet) {
                                    Some(_) => {
                                        self.stats.overflow += 1;
                                        self.stats.failed += 1;
                                    },
                                    None => self.stats.queued += 1,
                                }
                            },
                        }
                    }
                    /*
                     * // forwarding to host ring is not yet implemented
                     * if fw {
                     *  ring.set_flags(netmap::NR_FORWARD as u32);
                     *  }
                     */
                    if fw {
                        let to_forward = &self.lock;
                        while to_forward.load(Ordering::SeqCst) != 0 {
                            unsafe { libc::sched_yield() };
                            //println!("[RX#{}]: waiting for forwarding to happen, {} left", ring_num, to_forward.load(Ordering::SeqCst));
                        }
                    }
                }
            }
            if before.elapsed() >= ival {
                if let Some(ref metrics_client) = metrics_client {
                    let stats = &self.stats;
                    Self::update_metrics(stats, &mut metrics, seconds);
                    metrics_client.send(&metrics);
                }
                rate = self.stats.received/seconds;
                debug!("[RX#{}]: received: {}Pkts/s, dropped: {}Pkts/s, forwarded: {}Pkts/s, queued: {}Pkts/s, overflowed: {}Pkts/s, failed: {}Pkts/s",
                            self.ring_num, rate, self.stats.dropped/seconds,
                            self.stats.forwarded/seconds, self.stats.queued/seconds,
                            self.stats.overflow/seconds, self.stats.failed/seconds);
                self.stats.clear();
                before = time::Instant::now();
                self.update_routing_cache();
            }
        }
    }
}
