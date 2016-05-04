extern crate libc;
extern crate pnet;
extern crate crossbeam;
extern crate scheduler;
extern crate clap;

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
use pnet::util::MacAddr;

use scheduler::{CpuSet,Policy};

use clap::{Arg, App, SubCommand};

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

enum OutgoingPacket {
    Ingress(IngressPacket),
    Forwarded(([u8;2048], usize))
}

// helpers
fn get_cpu_count() -> usize {
    unsafe {
        libc::sysconf(libc::_SC_NPROCESSORS_ONLN) as usize
    }
}

fn tx_loop(ring_num: u16, cpu: usize, chan: mpsc::Receiver<OutgoingPacket>,
            netmap: &mut NetmapDescriptor) {
    let mut stats = TxStats::empty();
    println!("TX loop for ring {:?}", ring_num);
    println!("Tx rings: {:?}", netmap.get_tx_rings());

    scheduler::set_self_affinity(CpuSet::single(cpu)).expect("setting affinity failed");
    scheduler::set_self_policy(Policy::Fifo, 20).expect("setting sched policy failed");

    /* wait for card to reinitialize */
    thread::sleep_ms(1000);

    let mut before = time::Instant::now();
    let seconds: usize = 10;
    let ival = time::Duration::new(seconds as u64, 0);
    let mut rate: usize = 0;

    loop {
        let fd = netmap.get_fd();
        if let Some(_) = netmap.poll(netmap::Direction::Output) {
            for ring in netmap.tx_iter() {
                    for (slot, buf) in ring.iter(fd) {
                        let mut pkt = chan.recv().expect("Expected RX not to die on us");
                        match pkt {
                            OutgoingPacket::Ingress(pkt) => {
                                     if let Some(len) = packet::handle_reply(pkt, buf) {
                                        //println!("[TX#{}] SENDING PACKET\n", ring_num);
                                        slot.set_flags(netmap::NS_BUF_CHANGED as u16 | netmap::NS_REPORT as u16);
                                        slot.set_len(len as u16);
                                        stats.sent += 1;
                                    } else {
                                        stats.failed += 1;
                                        break;
                                    }
                                },
                            OutgoingPacket::Forwarded((mut tmp_buf, len)) => {
                                {
                                    let mut eth = MutableEthernetPacket::new(&mut tmp_buf[0..len]).unwrap();
                                    eth.set_destination(MacAddr::new(0x90, 0xe2, 0xba, 0xb8, 0x56, 0x89));
                                }
                                slot.set_flags(netmap::NS_BUF_CHANGED as u16 | netmap::NS_REPORT as u16);
                                slot.set_len(len as u16);
                                unsafe {
                                    ptr::copy_nonoverlapping(tmp_buf.as_ptr(), buf.as_mut_ptr(), len);
                                };
                                stats.sent += 1;
                            }
                        };
                        if rate <= 1000 {
                            break; // do tx sync on every packet if we receive
                            // small amount of packets
                        } else if rate <= 10000 && stats.sent % 64 == 0 {
                            break;
                        } else if rate <= 100_000 && stats.sent % 128 == 0 {
                            break;
                        } else if /* rate <= 1000_000 && */ stats.sent % 1024 == 0 {
                            break;
                        }
                    }
            }
        }
        if before.elapsed() >= ival {
            rate = stats.sent/seconds;
            println!("[TX#{}]: sent {}Pkts/s, failed {}Pkts/s", ring_num, rate, stats.failed/seconds);
            stats.clear();
            before = time::Instant::now();
        }
    }
}

fn host_rx_loop(ring_num: usize, netmap: &mut NetmapDescriptor) {
        println!("HOST RX loop for ring {:?}", ring_num);
        println!("Rx rings: {:?}", netmap.get_rx_rings());

        scheduler::set_self_affinity(CpuSet::single(ring_num)).expect("setting affinity failed");
        scheduler::set_self_policy(Policy::Fifo, 20).expect("setting sched policy failed");

        loop {
            if let Some(_) = netmap.poll(netmap::Direction::Input) {
                for ring in netmap.rx_iter() {
                    for (slot, _) in ring.iter() {
                        //println!("HOST RX pkt");
                        //packet::dump_input(&buf);
                        slot.set_flags(netmap::NS_FORWARD as u16);
                    }
                    ring.set_flags(netmap::NR_FORWARD as u32);
                }
            }
        }
}

fn rx_loop(ring_num: u16, cpu: usize, chan: mpsc::SyncSender<OutgoingPacket>,
        netmap: &mut NetmapDescriptor) {
        let mut stats = RxStats::empty();

        println!("RX loop for ring {:?}", ring_num);
        println!("Rx rings: {:?}", netmap.get_rx_rings());

        scheduler::set_self_affinity(CpuSet::single(cpu)).expect("setting affinity failed");
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
                        stats.received += 1;
                        match packet::handle_input(buf) {
                            Action::Drop => {
                                stats.dropped += 1;
                            },
                            Action::Forward => {
                                stats.forwarded += 1;
                                //slot.set_flags(netmap::NS_FORWARD as u16);
                                //fw = true;
                                let mut tmp = [0;2048];
                                let len = buf.len();
                                unsafe {
                                    ptr::copy_nonoverlapping(buf.as_ptr(), tmp.as_mut_ptr(), len);
                                };
                                chan.send(OutgoingPacket::Forwarded((tmp, len)));
                            },
                            Action::Reply(packet) => {
                                stats.queued += 1;
                                chan.send(OutgoingPacket::Ingress(packet));
                            },
                        }
                    }
                    /*if fw {
                        ring.set_flags(netmap::NR_FORWARD as u32);
                    }*/
                }
            }
            if before.elapsed() >= ival {
                println!("[RX#{}]: received: {}Pkts/s, dropped: {}Pkts/s, forwarded: {}Pkts/s, queued: {}Pkts/s",
                            ring_num, stats.received/seconds, stats.dropped/seconds,
                            stats.forwarded/seconds, stats.queued/seconds);
                stats.clear();
                before = time::Instant::now();
            }
        }
}

fn run(rx_iface: &str, tx_iface: &str) {
    use std::sync::{Mutex,Arc};

    let rx_nm = Arc::new(Mutex::new(NetmapDescriptor::new(rx_iface).unwrap()));
    let tx_nm = if rx_iface == tx_iface {
         rx_nm.clone()
     } else {
         Arc::new(Mutex::new(NetmapDescriptor::new(tx_iface).unwrap()))
    };
    let rx_count = {
        let rx_nm = rx_nm.lock().unwrap();
        rx_nm.get_rx_rings_count()
    };
    let tx_count = {
        let tx_nm = tx_nm.lock().unwrap();
        tx_nm.get_tx_rings_count()
    };
    println!("{} Rx rings @ {}, {} Tx rings @ {}", rx_count, rx_iface, tx_count, tx_iface);
    if tx_count < rx_count {
        panic!("We need at least as much Tx rings as Rx rings")
    }

    crossbeam::scope(|scope| {
        scope.spawn(|| loop {
            read_uptime();
            thread::sleep_ms(1000);
        });

        for ring in 0..rx_count {
            let ring = ring;
            let (tx, rx) = mpsc::sync_channel(1024 * 1024);

            let rx_nm = rx_nm.clone();
            scope.spawn(move || {
                println!("Starting RX thread for ring {} at {}", ring, rx_iface);
                let mut ring_nm = {
                    let nm = rx_nm.lock().unwrap();
                    nm.clone_ring(ring, Direction::Input).unwrap()
                };
                let cpu = ring as usize;
                rx_loop(ring, cpu, tx, &mut ring_nm)
            });

            let tx_nm = tx_nm.clone();
            scope.spawn(move || {
                println!("Starting TX thread for ring {} at {}", ring, tx_iface);
                let mut ring_nm = {
                    let nm = tx_nm.lock().unwrap();
                    nm.clone_ring(ring, Direction::Output).unwrap()
                };
                let cpu = rx_count as usize + ring as usize; /* HACK */
                tx_loop(ring, cpu, rx, &mut ring_nm)
            });
        }

        {
            let nm = rx_nm.clone();
            let ring = rx_count;

            scope.spawn(move || {
                    println!("Starting Host RX thread for ring {}", ring);
                    let mut ring_nm = {
                        let nm = nm.lock().unwrap();
                        nm.clone_ring(ring, Direction::Input).unwrap()
                    };
                    host_rx_loop(ring as usize, &mut ring_nm)
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
    let matches = App::new("syncookied")
                              .version("0.1")
                              .author("Alexander Polyakov <apolyakov@beget.ru>")
                              .arg(Arg::with_name("in")
                                   .short("i")
                                   .long("input-interface")
                                   .value_name("iface")
                                   .help("Interface to receive packets on")
                                   .required(true)
                                   .takes_value(true))
                               .arg(Arg::with_name("out")
                                   .short("o")
                                   .long("output-interface")
                                   .value_name("iface")
                                   .help("Interface to send packets on (input interface will be used if not set)")
                                   .takes_value(true))
                               .get_matches();

    let rx_iface = matches.value_of("in").expect("Expected valid input interface");
    let tx_iface = matches.value_of("out").unwrap_or(rx_iface);
    let ncpus = get_cpu_count();
    println!("interfaces: [Rx: {}, Tx: {}] cores: {}", rx_iface, tx_iface, ncpus);
    read_uptime();
    run(&rx_iface, &tx_iface);
}
