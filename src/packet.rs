use std::net::{IpAddr,Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};

use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, self};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket, MutableTcpOptionPacket, TcpOptionNumbers, self};
use pnet::packet::MutablePacket;
use pnet::packet::PacketSize;
use pnet::util::MacAddr;

use ::cookie;
use ::csum;

#[allow(dead_code)]
#[derive(Debug)]
pub enum Action {
    Drop,
    Forward,
    Reply(IngressPacket)
}

#[derive(Debug)]
pub struct IngressPacket {
    pub ether_source: MacAddr,
    pub ether_dest: MacAddr,
    pub ipv4_source: Ipv4Addr,
    pub ipv4_destination: Ipv4Addr,
    pub tcp_source: u16,
    pub tcp_destination: u16,
    pub tcp_timestamp: [u8;4],
    pub tcp_sequence: u32,
    pub tcp_mss: u32
}

impl Default for IngressPacket {
    fn default() -> Self {
        use std::mem;
        let pkt = unsafe { mem::zeroed() };
        pkt
    }
}

pub fn dump_input(packet_data: &[u8]) {
    let eth = EthernetPacket::new(packet_data).unwrap();
    println!("{:?}", &eth);
    match eth.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4 = Ipv4Packet::new(eth.payload());
            println!("{:?}", ipv4);
        },
        _ => {},
    };
}

pub fn handle_input(packet_data: &[u8]) -> Action {
    let mut pkt: IngressPacket = Default::default();
    let eth = EthernetPacket::new(packet_data).unwrap();
    match handle_ether_packet(&eth, &mut pkt) {
        Action::Reply(_) => Action::Reply(pkt),
        x@_ => x,
    }
}

#[inline]
pub fn handle_reply(pkt: IngressPacket, tx_slice: &mut [u8]) -> Option<usize> {
    let len = tx_slice.len();
    if len < 78 {
        None
    } else {
        Some(build_reply(&pkt, tx_slice))
    }
}

#[inline]
fn u32_to_oct(bits: u32) -> [u8; 4] {
    [(bits >> 24) as u8, (bits >> 16) as u8, (bits >> 8) as u8, bits as u8]
}

fn build_reply(pkt: &IngressPacket, reply: &mut [u8]) -> usize {
    let mut len = 0;
    let ether_len;
    /* build ethernet packet */
    let mut ether = MutableEthernetPacket::new(reply).unwrap();

    ether.set_source(pkt.ether_dest);
    ether.set_destination(pkt.ether_source);
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
    ip.set_source(pkt.ipv4_destination);
    ip.set_destination(pkt.ipv4_source);
    ip.set_checksum(0);
    len += ip.packet_size();

    {
        use std::ptr;
        /* build tcp packet */
        let cookie_time = ::TCP_COOKIE_TIME.load(Ordering::Relaxed);
        let (seq_num, mss_val) = cookie::generate_cookie_init_sequence(
            pkt.ipv4_source, pkt.ipv4_destination,
            pkt.tcp_source, pkt.tcp_destination, pkt.tcp_sequence,
            1460 /* FIXME */, cookie_time as u32);
        let mut tcp = MutableTcpPacket::new(&mut ip.payload_mut()[0..20 + 24]).unwrap();
        tcp.set_source(pkt.tcp_destination);
        tcp.set_destination(pkt.tcp_source);
        tcp.set_sequence(seq_num);
        tcp.set_acknowledgement(pkt.tcp_sequence + 1);
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
                mss.get_length_raw_mut()[0] = 4;
                let mss_payload = mss.payload_mut();
                mss_payload[0] = (mss_val >> 8) as u8;
                mss_payload[1] = (mss_val & 0xff) as u8;
            }
            { /* XXX hardcode sack */
                let mut sack = MutableTcpOptionPacket::new(&mut options[4..6]).unwrap();
                sack.set_number(TcpOptionNumbers::SACK_PERMITTED);
                sack.get_length_raw_mut()[0] = 2;
            }
            { /* Timestamp */
                let my_tcp_time = ::TCP_TIME_STAMP.load(Ordering::Relaxed) as u32;
                /*
                let in_options = tcp_in.get_options_iter();
                let mut their_time = &mut [0, 0, 0, 0][..];
                if let Some(ts_option) = in_options.filter(|opt| (*opt).get_number() == TcpOptionNumbers::TIMESTAMPS).nth(0) {
                    unsafe { ptr::copy_nonoverlapping::<u8>(ts_option.payload()[0..4].as_ptr(), their_time.as_mut_ptr(), 4) };
                }
                */
                let mut ts = MutableTcpOptionPacket::new(&mut options[6..16]).unwrap();
                ts.set_number(TcpOptionNumbers::TIMESTAMPS);
                ts.get_length_raw_mut()[0] = 10;
                let mut stamps = ts.payload_mut();
                unsafe {
                    ptr::copy_nonoverlapping::<u8>(u32_to_oct(cookie::synproxy_init_timestamp_cookie(7, 1, 0, my_tcp_time)).as_ptr(), stamps[..].as_mut_ptr(), 4);
                    ptr::copy_nonoverlapping::<u8>(pkt.tcp_timestamp.as_ptr(), stamps[4..].as_mut_ptr(), 4);
                }
            }
            { /* WSCALE */
                let mut ws = MutableTcpOptionPacket::new(&mut options[16..19]).unwrap();
                ws.set_number(TcpOptionNumbers::WSCALE);
                ws.get_length_raw_mut()[0] = 3;
                ws.set_data(&[7]);
            }
        }
        let cksum = {
            let tcp = tcp.to_immutable();
            csum::tcp_checksum(&tcp, pkt.ipv4_destination, pkt.ipv4_source, IpNextHeaderProtocols::Tcp).to_be()
        };
        tcp.set_checksum(cksum);
        len += tcp.packet_size();
    }

    ip.set_total_length((len - ether_len) as u16);
    let ip_cksum = {
        let ip = ip.to_immutable();
        csum::ip_checksum(&ip)
    };
    ip.set_checksum(ip_cksum);

    //println!("REPLY: {:?}", &ip);
    len
}

fn handle_tcp_packet(source: IpAddr, destination: IpAddr, packet: &[u8],
                     pkt: &mut IngressPacket) -> Action {
    use std::ptr;
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        //println!("TCP Packet: {}:{} > {}:{}; length: {}", source,
        //            tcp.get_source(), destination, tcp.get_destination(), packet.len());
        if tcp.get_syn() == 1 && tcp.get_ack() == 0 {
            //println!("TCP Packet: {:?}", tcp);
            pkt.tcp_source = tcp.get_source();
            pkt.tcp_destination = tcp.get_destination();
            pkt.tcp_sequence = tcp.get_sequence();

            let in_options = tcp.get_options_iter();
            if let Some(ts_option) = in_options.filter(|opt| (*opt).get_number() == TcpOptionNumbers::TIMESTAMPS).nth(0) {
                unsafe { ptr::copy_nonoverlapping::<u8>(ts_option.payload()[0..4].as_ptr(), pkt.tcp_timestamp.as_mut_ptr(), 4) };
            }
            pkt.tcp_mss = 1460; /* HACK */
            return Action::Reply(IngressPacket::default());
        }
        Action::Forward
    } else {
        println!("Malformed TCP Packet");
        Action::Drop
    }
}

fn handle_transport_protocol(source: IpAddr, destination: IpAddr,
                             protocol: IpNextHeaderProtocol, packet: &[u8],
                             pkt: &mut IngressPacket) -> Action {
    match protocol {
        IpNextHeaderProtocols::Tcp  => handle_tcp_packet(source, destination, packet, pkt),
        _ => Action::Forward,
    }
}

fn handle_ipv4_packet(ethernet: &EthernetPacket, pkt: &mut IngressPacket) -> Action {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        pkt.ipv4_source = header.get_source();
        pkt.ipv4_destination = header.get_destination();
        handle_transport_protocol(IpAddr::V4(header.get_source()),
                                  IpAddr::V4(header.get_destination()),
                                  header.get_next_level_protocol(),
                                  header.payload(),
                                  pkt)
    } else {
        println!("Malformed IPv4 Packet");
        Action::Drop
    }
}

fn handle_ether_packet(ethernet: &EthernetPacket, pkt: &mut IngressPacket) -> Action {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            pkt.ether_source = ethernet.get_source();
            pkt.ether_dest = ethernet.get_destination();
            handle_ipv4_packet(ethernet, pkt)
        },
        _                => Action::Forward,
    }
}
