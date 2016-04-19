extern crate libc;
extern crate pnet;
extern crate crossbeam;

use std::env;
use std::process;
use std::thread;

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};

use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, self};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket, MutableTcpOptionPacket, TcpOptionNumbers, self};
use pnet::packet::MutablePacket;
use pnet::packet::PacketSize;

mod netmap;
mod cookie;
mod sha1;
mod packet;
use netmap::{Action,NetmapDescriptor};

pub static TCP_TIME_STAMP: AtomicUsize = ATOMIC_USIZE_INIT;
pub static TCP_COOKIE_TIME: AtomicUsize = ATOMIC_USIZE_INIT;
pub static mut syncookie_secret: [[u32;17];2] = [[0;17];2];

// helpers
fn get_cpu_count() -> usize {
    unsafe { 
        libc::sysconf(libc::_SC_NPROCESSORS_ONLN) as usize
    } 
}

fn rx_loop(netmap: &mut NetmapDescriptor) {
        println!("Rx rings: {:?}", netmap.get_rx_rings());
        println!("Tx rings: {:?}", netmap.get_tx_rings());
        thread::sleep_ms(1000);
        //for _ in 0..1000 {
        loop {
            netmap.poll(packet::handle_input, packet::handle_reply);
        }
        //}
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
            scope.spawn(move || {
                println!("Starting thread for ring {}", ring);
                let mut ring_nm = {
                    let nm = nm.lock().unwrap();
                    nm.clone_ring(ring).unwrap()
                };
                rx_loop(&mut ring_nm)
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
