use std::time::{self,Duration};
use std::thread;
use ::mpsc;
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
    ring_num: u16,
    cpu: usize,
    chan_reply: mpsc::SyncSender<OutgoingPacket>,
    chan_fwd: mpsc::SyncSender<OutgoingPacket>,
    netmap: &'a mut NetmapDescriptor,
    lock: Arc<AtomicUsize>,
    stats: RxStats,
    mac: MacAddr,
}

impl<'a> Receiver<'a> {
    pub fn new(ring_num: u16, cpu: usize, chan_fwd: mpsc::SyncSender<OutgoingPacket>, chan_reply: mpsc::SyncSender<OutgoingPacket>,
               netmap: &'a mut NetmapDescriptor, lock: Arc<AtomicUsize>, mac: MacAddr) -> Self {
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
                                self.chan_fwd.send(OutgoingPacket::Forwarded((slot_ptr, buf_ptr, fwd_mac))).unwrap();
                                self.stats.forwarded += 1;
                                fw = true;
                            },
                            Action::Reply(packet) => {
                                self.stats.queued += 1;
                                self.chan_reply.send(OutgoingPacket::Ingress(packet)).unwrap();
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
                println!("[RX#{}]: received: {}Pkts/s, dropped: {}Pkts/s, forwarded: {}Pkts/s, queued: {}Pkts/s",
                            self.ring_num, rate, self.stats.dropped/seconds,
                            self.stats.forwarded/seconds, self.stats.queued/seconds);
                self.stats.clear();
                before = time::Instant::now();
                self.update_routing_cache();
            }
        }
    }
}
