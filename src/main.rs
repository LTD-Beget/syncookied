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
use netmap::{Action,NetmapDescriptor};

static TCP_TIME_STAMP: AtomicUsize = ATOMIC_USIZE_INIT;
static TCP_COOKIE_TIME: AtomicUsize = ATOMIC_USIZE_INIT;
pub static mut syncookie_secret: [[u32;17];2] = [[0;17];2];

// helpers
fn get_cpu_count() -> usize {
    unsafe { 
        libc::sysconf(libc::_SC_NPROCESSORS_ONLN) as usize
    } 
}

pub fn reply(rx_slice: &[u8], tx_slice: &mut [u8]) -> usize {
    let eth = EthernetPacket::new(rx_slice).unwrap();
    let ip = Ipv4Packet::new(eth.payload()).unwrap();
    let tcp = TcpPacket::new(ip.payload()).unwrap();
    build_reply(&eth, &ip, &tcp, tx_slice)
}

#[inline]
fn u32_to_oct(bits: u32) -> [u8; 4] {
    [(bits >> 24) as u8, (bits >> 16) as u8, (bits >> 8) as u8, bits as u8]
}

fn build_reply(eth_in: &EthernetPacket, ip_in: &Ipv4Packet, tcp_in: &TcpPacket, reply: &mut [u8]) -> usize {
    let mut len = 0;
    let ether_len;
    /* build ethernet packet */
    let mut ether = MutableEthernetPacket::new(reply).unwrap();
    
    ether.set_source(eth_in.get_destination());
    ether.set_destination(eth_in.get_source());
    ether.set_ethertype(EtherTypes::Ipv4);
    ether_len = ether.packet_size();
    len += ether_len;

    /* build ip packet */
    let mut ip = MutableIpv4Packet::new(ether.payload_mut()).unwrap();
    ip.set_version(4);
    ip.set_dscp(0);
    ip.set_ecn(0);
    ip.set_identification(0);
    ip.set_header_length(5);
    ip.set_ttl(126);
    ip.set_flags(2);
    ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip.set_source(ip_in.get_destination());
    ip.set_destination(ip_in.get_source());
    ip.set_checksum(0);
    len += ip.packet_size();

    {
        /* build tcp packet */
        let cookie_time = TCP_COOKIE_TIME.load(Ordering::Relaxed);
        let seq_num = cookie::generate_cookie_init_sequence(
            ip_in.get_source(), ip_in.get_destination(),
            tcp_in.get_source(), tcp_in.get_destination(), tcp_in.get_sequence(),
            1460 /* FIXME */, cookie_time as u32);
        let mut tcp = MutableTcpPacket::new(&mut ip.payload_mut()[0..20 + 24]).unwrap();
        tcp.set_source(tcp_in.get_destination());
        tcp.set_destination(tcp_in.get_source());
        tcp.set_sequence(seq_num);
        tcp.set_acknowledgement(tcp_in.get_sequence() + 1);
        tcp.set_window(65535);
        tcp.set_syn(1);
        tcp.set_ack(1);
        tcp.set_data_offset(11);
        tcp.set_checksum(0);
        {
            let options = tcp.get_options_raw_mut();
            {
                let mut mss = MutableTcpOptionPacket::new(&mut options[0..4]).unwrap();
                mss.set_number(TcpOptionNumbers::MSS);
                mss.set_length(&[4]);
                let mss_val: u16 = 1460; // FIXME
                mss.set_data(&[(mss_val >> 8) as u8, (mss_val & 0xff) as u8]);
            }
            { /* XXX hardcode sack */
                let mut sack = MutableTcpOptionPacket::new(&mut options[4..6]).unwrap();
                sack.set_number(TcpOptionNumbers::SACK_PERMITTED);
                sack.set_length(&[2]);
            }
            { /* Timestamp */
                let my_tcp_time = TCP_TIME_STAMP.load(Ordering::Relaxed) as u32;
                let in_options = tcp_in.get_options();
                let mut their_time = &[0, 0, 0, 0][..];
                if let Some(ts_option) = in_options.iter().filter(|opt| (*opt).get_number() == TcpOptionNumbers::TIMESTAMPS).nth(0) {
                    their_time = &ts_option.get_data()[0..4]; /* HACK */
                }
                let mut ts = MutableTcpOptionPacket::new(&mut options[6..16]).unwrap();
                ts.set_number(TcpOptionNumbers::TIMESTAMPS);
                ts.set_length(&[10]);
                let mut stamps: Vec<u8> = vec![];
                stamps.extend_from_slice(&u32_to_oct(cookie::synproxy_init_timestamp_cookie(7, 1, 0, my_tcp_time)));
                stamps.extend_from_slice(their_time);
                ts.set_data(&stamps);
            }
            { /* WSCALE */
                let mut ws = MutableTcpOptionPacket::new(&mut options[16..19]).unwrap();
                ws.set_number(TcpOptionNumbers::WSCALE);
                ws.set_length(&[3]);
                ws.set_data(&[7]);
            }
        }
        let cksum = {
            let tcp = tcp.to_immutable();
            tcp::ipv4_checksum(&tcp, ip_in.get_destination(), ip_in.get_source(), IpNextHeaderProtocols::Tcp)
        };
        tcp.set_checksum(cksum);
        len += tcp.packet_size();
    }

    ip.set_total_length((len - ether_len) as u16);
    let ip_cksum = {
        let ip = ip.to_immutable();
        ipv4::checksum(&ip)
    };
    ip.set_checksum(ip_cksum);

    len
}

fn handle_tcp_packet(source: IpAddr, destination: IpAddr, packet: &[u8]) -> Action {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        //println!("TCP Packet: {}:{} > {}:{}; length: {}", source,
        //            tcp.get_source(), destination, tcp.get_destination(), packet.len());
        if tcp.get_syn() == 1 && tcp.get_ack() == 0 {
            println!("TCP Packet: {:?}", tcp);
            return Action::Reply;
        }
        Action::Forward
    } else {
        println!("Malformed TCP Packet");
        Action::Drop
    }
}

fn handle_transport_protocol(source: IpAddr, destination: IpAddr,
                             protocol: IpNextHeaderProtocol, packet: &[u8]) -> Action {
    match protocol {
        IpNextHeaderProtocols::Tcp  => handle_tcp_packet(source, destination, packet),
        _ => Action::Forward,
    }
}

fn handle_ipv4_packet(ethernet: &EthernetPacket) -> Action {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(IpAddr::V4(header.get_source()),
                                  IpAddr::V4(header.get_destination()),
                                  header.get_next_level_protocol(),
                                  header.payload())
    } else {
        println!("Malformed IPv4 Packet");
        Action::Drop
    }
}

fn handle_ether_packet(ethernet: &EthernetPacket) -> Action {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(ethernet),
        _                => Action::Forward,
    }
}

fn handle_packet(packet_data: &[u8]) -> Action {
    let eth = EthernetPacket::new(packet_data).unwrap();
    handle_ether_packet(&eth)
}

fn rx_loop(netmap: &mut NetmapDescriptor) {
        println!("Rx rings: {:?}", netmap.get_rx_rings());
        println!("Tx rings: {:?}", netmap.get_tx_rings());
        thread::sleep_ms(1000);
        //for _ in 0..1000 {
        loop {
            netmap.poll(handle_packet);
        }
        //}
}

fn run(iface: &str) {
    let nm = NetmapDescriptor::new(iface).unwrap();
    println!("Rx rings: {}, Tx rings: {} flags: {}", nm.get_rx_rings_count(), nm.get_tx_rings_count(), nm.get_flags());

    crossbeam::scope(|scope| {
        scope.spawn(|| loop {
            read_uptime();
            thread::sleep_ms(1000);
        });

        for ring in 0..nm.get_rx_rings_count() {
            let mut ring_nm = nm.clone_ring(ring).unwrap();
            scope.spawn(move|| rx_loop(&mut ring_nm));
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
