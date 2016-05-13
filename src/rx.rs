use std::mem;
use std::time;
use std::thread;
use std::sync::mpsc;
use std::sync::mpsc::TryRecvError;
use std::sync::{Arc,Mutex};
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use ::netmap::{self,NetmapDescriptor,RxSlot,NetmapSlot};
use ::OutgoingPacket;
use ::packet;
use ::scheduler;
use ::scheduler::{CpuSet,Policy};
use ::pnet::util::MacAddr;
use ::pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use ::util;
use ::libc;
use ::packet::{Action,IngressPacket};

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
    chan: mpsc::SyncSender<OutgoingPacket>,
    netmap: &'a mut NetmapDescriptor,
    lock: Arc<AtomicUsize>,
    stats: RxStats,
    mac: MacAddr,
}

impl<'a> Receiver<'a> {
    pub fn new(ring_num: u16, cpu: usize, chan: mpsc::SyncSender<OutgoingPacket>,
               netmap: &'a mut NetmapDescriptor, lock: Arc<AtomicUsize>, mac: MacAddr) -> Self {
        Receiver {
            ring_num: ring_num,
            cpu: cpu,
            chan: chan,
            netmap: netmap,
            lock: lock,
            stats: RxStats::empty(),
            mac: mac,
        }
    }

    pub fn run(mut self) {
        println!("RX loop for ring {:?}", self.ring_num);
        println!("Rx rings: {:?}", self.netmap.get_rx_rings());

        util::set_thread_name(&format!("syncookied/rx{:02}", self.ring_num));

        scheduler::set_self_affinity(CpuSet::single(self.cpu)).expect("setting affinity failed");
        scheduler::set_self_policy(Policy::Fifo, 20).expect("setting sched policy failed");

        thread::sleep_ms(1000);

        let mut before = time::Instant::now();
        let seconds: usize = 10;
        let ival = time::Duration::new(seconds as u64, 0);
        let stats = &mut self.stats;

        loop {
            if let Some(_) = self.netmap.poll(netmap::Direction::Input) {
                if let Some(ring) = self.netmap.rx_iter().next() {
                    let mut fw = false;
                    for (slot, buf) in ring.iter() {
                        stats.received += 1;
                        match packet::handle_input(buf, self.mac) {
                            Action::Drop => {
                                stats.dropped += 1;
                            },
                            Action::Forward => {
                                let to_forward = &self.lock;

                                let slot_ptr: usize = slot as *mut RxSlot as usize;
                                let buf_ptr: usize = buf.as_ptr() as usize;

/*
                                println!("[RX#{}]: forwarded slot: {:x} buf: {:x}, buf_idx: {}",
                                    ring_num, slot_ptr, buf_ptr, slot.get_buf_idx());
*/
                                to_forward.fetch_add(1, Ordering::SeqCst);
                                self.chan.send(OutgoingPacket::Forwarded((slot_ptr, buf_ptr)));
                                stats.forwarded += 1;
                                fw = true;
                            },
                            Action::Reply(packet) => {
                                stats.queued += 1;
                                self.chan.send(OutgoingPacket::Ingress(packet));
                            },
                        }
                    }
                    /*if fw {
                        ring.set_flags(netmap::NR_FORWARD as u32);
                    }*/
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
                println!("[RX#{}]: received: {}Pkts/s, dropped: {}Pkts/s, forwarded: {}Pkts/s, queued: {}Pkts/s",
                            self.ring_num, stats.received/seconds, stats.dropped/seconds,
                            stats.forwarded/seconds, stats.queued/seconds);
                stats.clear();
                before = time::Instant::now();
            }
        }
    }
}
