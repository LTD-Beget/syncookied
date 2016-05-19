use std::time::{Duration};
use std::thread;
use std::net::Ipv4Addr;
use ::netmap::{self, NetmapDescriptor, NetmapSlot};
use ::packet;
use ::scheduler;
use ::scheduler::{CpuSet, Policy};
use ::pnet::util::MacAddr;
use ::util;

/// ARP sender tries to send 1 packet per second just to keep 
/// our rx interface's MAC address in switch's mac table.
/// Otherwise switch can get confused and broadcast our traffic
/// to all ports.
pub struct Sender<'a> {
    ring_num: u16,
    cpu: usize,
    netmap: &'a mut NetmapDescriptor,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
}

impl<'a> Sender<'a> {
    pub fn new(ring_num: u16, cpu: usize, netmap: &'a mut NetmapDescriptor,
            source_mac: MacAddr, source_ip: Ipv4Addr, dest_ip: Ipv4Addr) -> Sender<'a> {
        Sender {
            ring_num: ring_num,
            cpu: cpu,
            netmap: netmap,
            source_mac: source_mac,
            source_ip: source_ip,
            dest_ip: dest_ip,
        }
    }

    pub fn run(mut self) {
        println!("ARP TX loop for ring {:?} starting. Rings: {:?}", self.ring_num, self.netmap.get_tx_rings());

        util::set_thread_name(&format!("syncookied/arp{:02}", self.ring_num));

        scheduler::set_self_affinity(CpuSet::single(self.cpu)).expect("setting affinity failed");
        scheduler::set_self_policy(Policy::Fifo, 20).expect("setting sched policy failed");

        /* wait for card to reinitialize */
        thread::sleep(Duration::new(1, 0));
        println!("[ARP-TX#{}] started", self.ring_num);

        loop {
            if let Some(_) = self.netmap.poll(netmap::Direction::Output) {
                if let Some(ring) = self.netmap.tx_iter().next() {
                    let mut tx_iter = ring.iter();

                    /* send one packet */
                    if let Some((slot, buf)) = tx_iter.next() {
                        if let Some(len) = packet::handle_arp(self.source_mac.clone(),
                                                              self.source_ip,
                                                              self.dest_ip,
                                                              buf)
                        {
                            slot.set_flags(netmap::NS_BUF_CHANGED as u16 /* | netmap::NS_REPORT as u16 */);
                            slot.set_len(len as u16);
                            println!("[ARP-TX#{}] arp request sent", self.ring_num);
                        }
                    }
                }
            }
            thread::sleep(Duration::new(1, 0));
        }
    }
}
