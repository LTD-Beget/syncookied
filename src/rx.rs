use std::time::{self,Duration};
use std::thread;
use ::spsc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use ::netmap::{self, NetmapDescriptor, RxSlot};
use ::OutgoingPacket;
use ::packet;
use ::scheduler;
use ::scheduler::{CpuSet, Policy};
use ::pnet::util::MacAddr;
use ::util;
use ::libc;
use ::packet::Action;

#[derive(Debug,Default)]
struct RxStats {
    pub received: usize,
    pub dropped: usize,
    pub forwarded: usize,
    pub queued: usize,
    pub overflow: usize,
    pub failed: usize,
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
    chan_reply: spsc::Producer<OutgoingPacket>,
    chan_fwd: Option<spsc::Producer<OutgoingPacket>>,
    netmap: &'a mut NetmapDescriptor,
    stats: RxStats,
    lock: Arc<AtomicUsize>,
    mac: MacAddr,
    ring_num: u16,
}

#[inline(always)]
fn adaptive_push(chan: &spsc::Producer<OutgoingPacket>, pkt: OutgoingPacket, retries: usize) -> Option<OutgoingPacket> {
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
    match chan.try_push(packet) {
        None => None,
        x => { 
            return x;
        },
    }
}


impl<'a> Receiver<'a> {
    pub fn new(ring_num: u16, cpu: usize,
               chan_fwd: Option<spsc::Producer<OutgoingPacket>>,
               chan_reply: spsc::Producer<OutgoingPacket>,
               netmap: &'a mut NetmapDescriptor,
               lock: Arc<AtomicUsize>,
               mac: MacAddr) -> Self {
        Receiver {
            ring_num: ring_num,
            cpu: cpu,
            chan_fwd: chan_fwd,
            chan_reply: chan_reply,
            netmap: netmap,
            lock: lock,
            stats: RxStats::empty(),
            mac: mac,
        }
    }

    fn update_routing_cache(&mut self) {
        ::RoutingTable::sync_tables();
    }

    pub fn run(mut self) {
        println!("RX loop for ring {:?}", self.ring_num);
        println!("Rx rings: {:?}", self.netmap.get_rx_rings());

        util::set_thread_name(&format!("syncookied/rx{:02}", self.ring_num));

        scheduler::set_self_affinity(CpuSet::single(self.cpu)).expect("setting affinity failed");
        scheduler::set_self_policy(Policy::Fifo, 20).expect("setting sched policy failed");

        /* wait for card to reinitialize */
        thread::sleep(Duration::new(1, 0));
        println!("[RX#{}] started", self.ring_num);

        self.update_routing_cache();

        let mut before = time::Instant::now();
        let seconds: usize = 2;
        let mut rate: usize = 0;
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
                                let chan = match self.chan_fwd {
                                    Some(ref chan) => chan,
                                    None => &self.chan_reply,
                                };
                                let packet = OutgoingPacket::Forwarded((slot_ptr, buf_ptr, fwd_mac));
                                match adaptive_push(chan, packet, 1) {
                                    Some(_) => self.stats.failed += 1,
                                    None => {
                                        self.stats.forwarded += 1;
                                        fw = true;
                                    },
								}
                            },
                            Action::Reply(packet) => {
                                let packet = OutgoingPacket::Ingress(packet);
                                match self.chan_reply.try_push(packet) {
                                    Some(pkt) => {
                                        self.stats.overflow += 1;
                                        match self.chan_fwd {
                                            /* fall back to chan fwd if available */
                                            Some(ref chan) => match adaptive_push(chan, pkt, 1) {
                                                None => self.stats.queued += 1,
                                                Some(_) => self.stats.failed += 1,
                                            },
                                            /* nothing we can do, fail */
                                            None => {
                                                self.stats.failed += 1;
                                            }
                                        }
                                    },
                                    None => self.stats.queued += 1,
                                }
                                /*
                                match self.chan_reply.try_push(OutgoingPacket::Ingress(packet)) {
                                    None => self.stats.queued += 1,
                                    Some(pkt) => {
                                        self.stats.overflow += 1;
                                        match self.chan_fwd {
                                            /* fall back to chan fwd if available */
                                            Some(ref chan) => match chan.try_push(pkt) {
                                                    None => self.stats.queued += 1,
                                                    Some(_) => { 
                                                        self.stats.failed += 1;
                                                    },
                                            },
                                            /* nothing to do, fail */
                                            None => {
                                                self.stats.failed += 1;
                                            }
                                        }
                                    },
                                }
                                */
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
                rate = self.stats.received/seconds;
                println!("[RX#{}]: received: {}Pkts/s, dropped: {}Pkts/s, forwarded: {}Pkts/s, queued: {}Pkts/s, overflowed: {}Pkts/s, failed: {}Pkts/s",
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
