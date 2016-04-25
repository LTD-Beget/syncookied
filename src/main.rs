extern crate libc;
extern crate pnet;
extern crate crossbeam;
extern crate scheduler;

use std::env;
use std::ptr;
use std::process;
use std::thread;
use std::time;
use std::sync::mpsc;

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};

use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, self};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket, MutableTcpOptionPacket, TcpOptionNumbers, self};
use pnet::packet::MutablePacket;
use pnet::packet::PacketSize;

use scheduler::{CpuSet,Policy};

mod netmap;
mod cookie;
mod sha1;
mod packet;
mod csum;
use packet::{Action,IngressPacket};
use netmap::{Direction,NetmapDescriptor,NetmapRing,NetmapSlot};

pub static TCP_TIME_STAMP: AtomicUsize = ATOMIC_USIZE_INIT;
pub static TCP_COOKIE_TIME: AtomicUsize = ATOMIC_USIZE_INIT;
pub static mut syncookie_secret: [[u32;17];2] = [[0;17];2];

// helpers
fn get_cpu_count() -> usize {
    unsafe {
        libc::sysconf(libc::_SC_NPROCESSORS_ONLN) as usize
    }
}

fn tx_loop(ring_num: usize, chan: mpsc::Receiver<IngressPacket>,
            netmap: &mut NetmapDescriptor) {
    println!("TX loop for ring {:?}", ring_num);
    println!("Tx rings: {:?}", netmap.get_tx_rings());

    scheduler::set_self_affinity(CpuSet::single(ring_num)).expect("setting affinity failed");
    scheduler::set_self_policy(Policy::Fifo, 20).expect("setting sched policy failed");

    /* wait for card to reinitialize */
    thread::sleep_ms(1000);

    loop {
        if let Some(_) = netmap.poll(netmap::Direction::Output) {
            for ring in netmap.tx_iter() {
                    for (slot, buf) in ring.iter() {
                        let pkt = chan.recv().expect("Expected RX not to die on us");
                        let len = packet::handle_reply(pkt, buf);
                        slot.set_flags(netmap::NS_BUF_CHANGED as u16 /* | netmap::NS_REPORT as u16 */);
                        slot.set_len(len as u16);
                        //println!("TX{} Sent reply: {}", ring_num, len);
                        break; // TODO
                    }
            }
        }
    }
}

fn rx_loop(ring: usize, chan: mpsc::SyncSender<IngressPacket>,
        netmap: &mut NetmapDescriptor) {
        let mut stats = netmap::Stats::empty();

        println!("Rx rings: {:?}", netmap.get_rx_rings());

        scheduler::set_self_affinity(CpuSet::single(ring)).expect("setting affinity failed");
        scheduler::set_self_policy(Policy::Fifo, 20).expect("setting sched policy failed");

        thread::sleep_ms(1000);

        let mut before = time::Instant::now();
        let seconds: usize = 10;
        let ival = time::Duration::new(seconds as u64, 0);

        loop {
            if let Some(_) = netmap.poll(netmap::Direction::Input) {
                for ring in netmap.rx_iter() {
                    let mut fw = false;
                    for (slot, buf) in ring.iter() {
                        match packet::handle_input(buf) {
                            Action::Drop => {},
                            Action::Forward => {
                                slot.set_flags(netmap::NS_FORWARD as u16);
                                fw = true;
                            },
                            Action::Reply(packet) => {
                                chan.send(packet);
                            }
                        }
                    }
                    if fw {
                        ring.set_flags(netmap::NR_FORWARD as u32);
                    }
                }
            }
        }
}

fn run(iface: &str) {
    use std::sync::{Mutex,Arc};

    let nm = NetmapDescriptor::new(iface).unwrap();
    let rx_count = nm.get_rx_rings_count();
    let tx_count = nm.get_tx_rings_count();
    println!("Rx rings: {}, Tx rings: {}", rx_count, tx_count);

    let nm = Arc::new(Mutex::new(nm));
    crossbeam::scope(|scope| {
        scope.spawn(|| loop {
            read_uptime();
            thread::sleep_ms(1000);
        });

        for ring in 0..rx_count {
            let nm = &nm;
            let ring = ring.clone();
            let (tx, rx) = mpsc::sync_channel(1024);

            scope.spawn(move || {
                println!("Starting RX thread for ring {}", ring);
                let mut ring_nm = {
                    let nm = nm.lock().unwrap();
                    nm.clone_ring(ring, Direction::Input).unwrap()
                };
                rx_loop(ring as usize, tx, &mut ring_nm)
            });

            scope.spawn(move || {
                println!("Starting TX thread for ring {}", ring);
                let mut ring_nm = {
                    let nm = nm.lock().unwrap();
                    nm.clone_ring(ring, Direction::Output).unwrap()
                };
                tx_loop(ring as usize, rx, &mut ring_nm)
            });
        }
    });
}

pub fn read_uptime() {
    use std::fs::File;
    use std::io::prelude::*;
    use std::io::BufReader;
    let file = File::open("/proc/beget_uptime").unwrap();
    let reader = BufReader::new(file);
    let mut jiffies = 0;
    let mut tcp_cookie_time = 0;
    //let mut syncookie_secret: [[u32;17]; 2] = [[0;17]; 2];
    for (idx, line) in reader.lines().enumerate() {
        let line = line.unwrap();
        match idx {
            0 => {
                for (idx, word) in line.split(' ').enumerate() {
                    match idx {
                        0 => { jiffies = word.parse::<u64>().unwrap() },
                        1 => { tcp_cookie_time = word.parse::<u32>().unwrap() },
                        _ => {},
                    }
                }
            },
            1 => {
                for (idx, word) in line.split('.').enumerate() {
                    if word == "" {
                        continue;
                    }
                    unsafe { syncookie_secret[0][idx] = u32::from_str_radix(word, 16).unwrap() };
                }
            },
            2 => {
                for (idx, word) in line.split('.').enumerate() {
                    if word == "" {
                        continue;
                    }
                    unsafe { syncookie_secret[1][idx] = u32::from_str_radix(word, 16).unwrap() };
                }
            },
            _ => {},
        }
    }
    //println!("jiffies: {}, tcp_cookie_time: {}, syncookie_secret: {:?}", jiffies, tcp_cookie_time, unsafe { syncookie_secret });
    TCP_TIME_STAMP.store(jiffies as usize & 0xffffffff, Ordering::SeqCst);
    TCP_COOKIE_TIME.store(tcp_cookie_time as usize, Ordering::SeqCst);
}

fn main() {
    let iface = env::args().nth(1).unwrap();
    let ncpus = get_cpu_count();
    println!("interface: {} cores: {}", iface, ncpus);
    read_uptime();
    run(&iface);
}
