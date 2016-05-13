#[macro_use]
extern crate lazy_static;
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
use std::mem;
use std::sync::mpsc;
use std::sync::mpsc::TryRecvError;
use std::sync::{Arc,Mutex};

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
mod util;
mod tx;
mod rx;
use packet::{Action,IngressPacket};
use netmap::{Direction,NetmapDescriptor,NetmapRing,NetmapSlot,TxSlot,RxSlot};

pub static TCP_TIME_STAMP: AtomicUsize = ATOMIC_USIZE_INIT;
pub static TCP_COOKIE_TIME: AtomicUsize = ATOMIC_USIZE_INIT;
pub static mut syncookie_secret: [[u32;17];2] = [[0;17];2];

pub enum OutgoingPacket {
    Ingress(IngressPacket),
    Forwarded((usize, usize)),
}

fn run(rx_iface: &str, tx_iface: &str, rx_mac: MacAddr, fwd_mac: MacAddr) {
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
            let pair = Arc::new(AtomicUsize::new(0));
            let rx_pair = pair.clone();

            let rx_nm = rx_nm.clone();

            scope.spawn(move || {
                println!("Starting RX thread for ring {} at {}", ring, rx_iface);
                let mut ring_nm = {
                    let nm = rx_nm.lock().unwrap();
                    nm.clone_ring(ring, Direction::Input).unwrap()
                };
                let cpu = ring as usize;
                rx::Receiver::new(ring, cpu, tx, &mut ring_nm, rx_pair).run();
            });

            let tx_nm = tx_nm.clone();
            scope.spawn(move || {
                println!("Starting TX thread for ring {} at {}", ring, tx_iface);
                let mut ring_nm = {
                    let nm = tx_nm.lock().unwrap();
                    nm.clone_ring(ring, Direction::Output).unwrap()
                };
                let cpu = /* rx_count as usize + */ ring as usize; /* HACK */
                tx::Sender::new(ring, cpu, rx, &mut ring_nm, pair, rx_mac.clone(), fwd_mac).run();
            });
        }

        /*
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
        */
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
                               .arg(Arg::with_name("in-mac")
                                    .short("I")
                                    .required(true)
                                    .long("input-mac")
                                    .value_name("macaddr")
                                    .help("Input interface mac address")
                                    .takes_value(true))
                               .arg(Arg::with_name("fwd-mac")
                                    .short("F")
                                    .required(true)
                                    .long("forward-to")
                                    .value_name("macaddr")
                                    .help("Mac address we forward to")
                                    .takes_value(true))
                               .get_matches();

    let rx_iface = matches.value_of("in").expect("Expected valid input interface");
    let tx_iface = matches.value_of("out").unwrap_or(rx_iface);
    let rx_mac = matches.value_of("in-mac").map(util::parse_mac).expect("Expected valid mac").unwrap();
    let fwd_mac = matches.value_of("fwd-mac").map(util::parse_mac).expect("Expected valid mac").unwrap();
    let ncpus = util::get_cpu_count();
    println!("interfaces: [Rx: {}/{}, Tx: {}] Fwd to: {} Cores: {}", rx_iface, rx_mac, tx_iface, fwd_mac, ncpus);
    read_uptime();
    run(&rx_iface, &tx_iface, rx_mac, fwd_mac);
}
