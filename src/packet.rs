use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};

use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, self};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket, MutableTcpOptionPacket, TcpOptionNumbers, self};
use pnet::packet::MutablePacket;
use pnet::packet::PacketSize;

use ::netmap::{Action,NetmapDescriptor};
use ::cookie;

pub fn handle_input(packet_data: &[u8]) -> Action {
    let eth = EthernetPacket::new(packet_data).unwrap();
    handle_ether_packet(&eth)
}

pub fn handle_reply(rx_slice: &[u8], tx_slice: &mut [u8]) -> usize {
    /* HACK */
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
        let cookie_time = ::TCP_COOKIE_TIME.load(Ordering::Relaxed);
        let (seq_num, mss_val) = cookie::generate_cookie_init_sequence(
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
                mss.get_length_raw_mut()[0] = 4;
                mss.set_data(&[(mss_val >> 8) as u8, (mss_val & 0xff) as u8]);
            }
            { /* XXX hardcode sack */
                let mut sack = MutableTcpOptionPacket::new(&mut options[4..6]).unwrap();
                sack.set_number(TcpOptionNumbers::SACK_PERMITTED);
                sack.get_length_raw_mut()[0] = 2;
            }
            { /* Timestamp */
                let my_tcp_time = ::TCP_TIME_STAMP.load(Ordering::Relaxed) as u32;
                let in_options = tcp_in.get_options_iter();
                let mut their_time = &mut [0, 0, 0, 0][..];
                if let Some(ts_option) = in_options.filter(|opt| (*opt).get_number() == TcpOptionNumbers::TIMESTAMPS).nth(0) {
                    unsafe { ptr::copy_nonoverlapping::<u8>(ts_option.payload()[0..4].as_ptr(), their_time.as_mut_ptr(), 4) };
                }
                let mut ts = MutableTcpOptionPacket::new(&mut options[6..16]).unwrap();
                ts.set_number(TcpOptionNumbers::TIMESTAMPS);
                ts.get_length_raw_mut()[0] = 10;
                let mut stamps = ts.payload_mut();
                use std::ptr;
                unsafe {
                    ptr::copy_nonoverlapping::<u8>(u32_to_oct(cookie::synproxy_init_timestamp_cookie(7, 1, 0, my_tcp_time)).as_ptr(), stamps[..].as_mut_ptr(), 4);
                    ptr::copy_nonoverlapping::<u8>(their_time.as_ptr(), stamps[4..].as_mut_ptr(), 4);
                }
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
            //println!("TCP Packet: {:?}", tcp);
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
