use std::net::Ipv4Addr;

use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::arp::{MutableArpPacket, ArpOperations, ArpHardwareTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket, MutableTcpOptionPacket, TcpOptionNumbers, TcpFlags};
use pnet::packet::MutablePacket;
use pnet::packet::PacketSize;
use pnet::util::MacAddr;

use ::cookie;
use ::csum;

pub const MIN_REPLY_BUF_LEN: usize = 74;

lazy_static! {
    static ref REPLY_TEMPLATE: Vec<u8> = {
        let mut data: Vec<u8> = vec![0;MIN_REPLY_BUF_LEN];
        /* prepare data common to all packets beforehand */
        {
            let pkt = IngressPacket {
                ether_source: MacAddr::new(0, 0, 0, 0, 0, 0),
                ipv4_source: Ipv4Addr::new(127, 0, 0, 1),
                ipv4_destination: Ipv4Addr::new(127, 0, 0, 1),
                tcp_source: 0,
                tcp_destination: 0,
                tcp_timestamp: [0, 0, 0, 0],
                tcp_sequence: 0,
                tcp_mss: 1460,
            };
            build_reply(&pkt, MacAddr::new(0, 0, 0, 0, 0, 0), &mut data);
        }
        data
    };
    static ref REPLY_TEMPLATE_SLICE: &'static [u8] = {
        &REPLY_TEMPLATE[12..MIN_REPLY_BUF_LEN]
    };
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Action {
    Drop,
    Forward(MacAddr),
    Reply(IngressPacket)
}

#[derive(Debug)]
pub struct IngressPacket {
    pub ether_source: MacAddr,
    pub ipv4_source: Ipv4Addr,
    pub ipv4_destination: Ipv4Addr,
    pub tcp_source: u16,
    pub tcp_destination: u16,
    pub tcp_timestamp: [u8;4],
    pub tcp_sequence: u32,
    pub tcp_mss: u16
}

impl Default for IngressPacket {
    fn default() -> Self {
        use std::mem;
        let pkt = unsafe { mem::zeroed() };
        pkt
    }
}

#[allow(dead_code)]
pub fn dump_input(packet_data: &[u8]) {
    let eth = EthernetPacket::new(packet_data).unwrap();
    println!("{:?}", &eth);
    match eth.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4 = Ipv4Packet::new(eth.payload()).unwrap();
            println!("{:?}", ipv4);
            match ipv4.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp  => { 
                    let tcp = TcpPacket::new(ipv4.payload()).unwrap();
                    println!("{:?}", tcp);
                },
                _ => {},
            }
        },
        _ => {},
    };
}

pub fn handle_input(packet_data: &[u8], mac: MacAddr) -> Action {
    let mut pkt: IngressPacket = Default::default();
    if let Some(eth) = EthernetPacket::new(packet_data) {
        match handle_ether_packet(&eth, &mut pkt, mac) {
            Action::Reply(_) => Action::Reply(pkt),
            x@_ => x,
        }
    } else {
        Action::Drop
    }
}

#[inline]
pub fn handle_reply(pkt: &IngressPacket, source_mac: MacAddr, tx_slice: &mut [u8]) -> Option<usize> {
    Some(build_reply_with_template(pkt, source_mac, tx_slice))
}

#[inline]
fn u32_to_oct(bits: u32) -> [u8; 4] {
    [(bits >> 24) as u8, (bits >> 16) as u8, (bits >> 8) as u8, bits as u8]
}

fn build_reply_fast(pkt: &IngressPacket, source_mac: MacAddr, reply: &mut [u8]) -> usize {
    /* build ethernet packet */
    let mut ether = MutableEthernetPacket::new(reply).unwrap();

    ether.set_source(source_mac);
    ether.set_destination(pkt.ether_source);

    /* build ip packet */
    let mut ip = MutableIpv4Packet::new(ether.payload_mut()).unwrap();
    ip.set_source(pkt.ipv4_destination);
    ip.set_destination(pkt.ipv4_source);
    ip.set_checksum(0);

    {
        use std::mem;
        /* build tcp packet */
        let mut cookie_time = 0;
        let mut secret: [[u32;17];2] = unsafe { mem::uninitialized() };
        ::RoutingTable::with_host_config(pkt.ipv4_destination, |hc| {
            cookie_time = hc.tcp_cookie_time;
            secret[0].copy_from_slice(&hc.syncookie_secret[0][0..17]);
            secret[1].copy_from_slice(&hc.syncookie_secret[1][0..17]);
        });
        let (seq_num, mss_val) = cookie::generate_cookie_init_sequence(
            pkt.ipv4_source, pkt.ipv4_destination,
            pkt.tcp_source, pkt.tcp_destination, pkt.tcp_sequence,
            pkt.tcp_mss, cookie_time as u32, &secret);
        let mut tcp = MutableTcpPacket::new(&mut ip.payload_mut()[0..20 + 20]).unwrap();
        tcp.set_source(pkt.tcp_destination);
        tcp.set_destination(pkt.tcp_source);
        tcp.set_sequence(seq_num);
        tcp.set_acknowledgement(pkt.tcp_sequence + 1);
        tcp.set_checksum(0);

        {
            let options = tcp.get_options_raw_mut();
            { /* Timestamp */
                let mut my_tcp_time = 0;
                ::RoutingTable::with_host_config(pkt.ipv4_destination, |hc| my_tcp_time = hc.tcp_timestamp as u32);
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
                stamps[0..4].copy_from_slice(&u32_to_oct(cookie::synproxy_init_timestamp_cookie(7, 1, 0, my_tcp_time))[0..4]);
                stamps[4..8].copy_from_slice(&pkt.tcp_timestamp[0..4]);
            }
        }
        let cksum = {
            let tcp = tcp.to_immutable();
            csum::tcp_checksum(&tcp, pkt.ipv4_destination, pkt.ipv4_source, IpNextHeaderProtocols::Tcp).to_be()
        };
        tcp.set_checksum(cksum);
    }

    let ip_cksum = {
        let ip = ip.to_immutable();
        csum::ip_checksum(&ip).to_be()
    };
    ip.set_checksum(ip_cksum);

    //println!("REPLY: {:?}", &ip);
    //len
    MIN_REPLY_BUF_LEN // ip.get_total_length()
}

fn build_reply_with_template(pkt: &IngressPacket, source_mac: MacAddr, reply: &mut [u8]) -> usize {
    reply[12..MIN_REPLY_BUF_LEN].copy_from_slice(&REPLY_TEMPLATE[12..MIN_REPLY_BUF_LEN]);
    build_reply_fast(pkt, source_mac, reply)
    //reply[12..78].copy_from_slice(&REPLY_TEMPLATE[12..78]);
    //build_reply_fast(pkt, source_mac, reply)
    //build_reply_with_builder(pkt, source_mac, reply)
}

pub fn build_reply(pkt: &IngressPacket, source_mac: MacAddr, reply: &mut [u8]) -> usize {
    let mut len = 0;
    let ether_len;
    /* build ethernet packet */
    let mut ether = MutableEthernetPacket::new(reply).unwrap();

    ether.set_source(source_mac);
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
        use std::mem;
        /* build tcp packet */
        let mut cookie_time = 0;
        let mut secret: [[u32;17];2] = unsafe { mem::uninitialized() };

        ::RoutingTable::with_host_config(pkt.ipv4_destination, |hc| {
            cookie_time = hc.tcp_cookie_time;
            secret[0].copy_from_slice(&hc.syncookie_secret[0][0..17]);
            secret[1].copy_from_slice(&hc.syncookie_secret[1][0..17]);
        });
        let (seq_num, mss_val) = cookie::generate_cookie_init_sequence(
            pkt.ipv4_source, pkt.ipv4_destination,
            pkt.tcp_source, pkt.tcp_destination, pkt.tcp_sequence,
            pkt.tcp_mss, cookie_time as u32, &secret);
        let mut tcp = MutableTcpPacket::new(&mut ip.payload_mut()[0..20 + 20]).unwrap();
        tcp.set_source(pkt.tcp_destination);
        tcp.set_destination(pkt.tcp_source);
        tcp.set_sequence(seq_num);
        tcp.set_acknowledgement(pkt.tcp_sequence + 1);
        tcp.set_window(65535);
        tcp.set_flags(TcpFlags::SYN | TcpFlags::ACK);
        tcp.set_data_offset(10);
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
                let mut my_tcp_time = 0;
                ::RoutingTable::with_host_config(pkt.ipv4_destination, |hc| my_tcp_time = hc.tcp_timestamp as u32);
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
            { /* Padding */
                let mut ts = MutableTcpOptionPacket::new(&mut options[16..17]).unwrap();
                ts.set_number(TcpOptionNumbers::NOP);
            }
            { /* WSCALE */
                let mut ws = MutableTcpOptionPacket::new(&mut options[17..20]).unwrap();
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
        csum::ip_checksum(&ip).to_be()
    };
    ip.set_checksum(ip_cksum);

    //println!("REPLY: {:?}", &ip);
    len
}

fn handle_tcp_packet(packet: &[u8], fwd_mac: MacAddr, pkt: &mut IngressPacket) -> Action {
    use std::ptr;
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        //println!("TCP Packet: {}:{} > {}:{}; length: {}", source,
        //            tcp.get_source(), destination, tcp.get_destination(), packet.len());
        if tcp.get_flags() & (TcpFlags::SYN | TcpFlags::ACK) == TcpFlags::SYN {
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
        /* disable stateful firewall for now */
        if false /* tcp.get_flags() & TcpFlags::ACK == TcpFlags::ACK */ {
            let cookie = tcp.get_acknowledgement() - 1;
            let tcp_saddr = tcp.get_source();
            let tcp_daddr = tcp.get_destination();
            let ip_saddr = pkt.ipv4_source;
            let ip_daddr = pkt.ipv4_destination;
            let seq = tcp.get_sequence();
            let mut action = Action::Drop;
            let mut new = false;

            ::RoutingTable::with_host_config(ip_daddr, |hc| {
                if hc.state_table.get_state(ip_saddr, tcp_saddr, tcp_daddr).is_some() {
                    //println!("Have state for {}:{} -> {}:{}, passing", ip_saddr, tcp_saddr, ip_daddr, tcp_daddr);
                    action = Action::Forward(fwd_mac)
                } else {
                    //println!("State for {}:{} -> {}:{} not found", ip_saddr, tcp_saddr, ip_daddr, tcp_daddr);
                    /* println!("Check cookie for {}:{} -> {}:{}",
                             ip_saddr, tcp_saddr, ip_daddr, tcp_daddr,
                             ); */
                    let res = cookie::cookie_check(ip_saddr, ip_daddr, tcp_saddr, tcp_daddr, 
                                                   seq, cookie);
                    //println!("check result is {:?}", res);
                    if res.is_some() {
                        new = true;
                        action = Action::Forward(fwd_mac);
                    } else {
                        //println!("Bad cookie, drop");
                    }
                }
            });
            if new {
                ::RoutingTable::with_host_config_mut(ip_daddr, |hc| {
                    hc.state_table.add_state(ip_saddr, tcp_saddr, tcp_daddr, 1);
                });
            }
            //println!("{}:{} -> {}:{} action: {:?}", ip_saddr, tcp_saddr, ip_daddr, tcp_daddr, action);
            return action;
        }
        Action::Forward(fwd_mac)
    } else {
        println!("Malformed TCP Packet");
        Action::Drop
    }
}

fn handle_transport_protocol(protocol: IpNextHeaderProtocol, packet: &[u8],
                             fwd_mac: MacAddr,
                             pkt: &mut IngressPacket) -> Action {
    match protocol {
        IpNextHeaderProtocols::Tcp  => handle_tcp_packet(packet, fwd_mac, pkt),
        _ => Action::Forward(fwd_mac),
    }
}

fn handle_ipv4_packet(ethernet: &EthernetPacket, pkt: &mut IngressPacket) -> Action {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        pkt.ipv4_source = header.get_source();
        pkt.ipv4_destination = header.get_destination();
        let mut fwd_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
        if ::RoutingTable::with_host_config(pkt.ipv4_destination, |hc| {
            fwd_mac = hc.mac;
        }) == None {
            return Action::Drop;
        }
        handle_transport_protocol(header.get_next_level_protocol(),
                                  header.payload(),
                                  fwd_mac,
                                  pkt)
    } else {
        println!("Malformed IPv4 Packet");
        Action::Drop
    }
}

#[inline]
fn handle_ether_packet(ethernet: &EthernetPacket, pkt: &mut IngressPacket, mac: MacAddr) -> Action {
    let bytes = ethernet.packet();
    let mut tmp_mac_arr = [0; 6];
    tmp_mac_arr.copy_from_slice(&bytes[0..6]);
    let mac_dest = MacAddr(tmp_mac_arr);

    if mac_dest != mac {
        return Action::Drop;
    }
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            tmp_mac_arr.copy_from_slice(&bytes[6..12]);
            pkt.ether_source = MacAddr(tmp_mac_arr);
            handle_ipv4_packet(ethernet, pkt)
        },
        _  => Action::Drop,
    }
}

pub fn handle_arp(source_mac: MacAddr, source_ip: Ipv4Addr, dest_ip: Ipv4Addr, buf: &mut [u8]) -> Option<usize> {
    let mut ether = MutableEthernetPacket::new(buf).unwrap();
    let mut len = 0;

    ether.set_source(source_mac);
    ether.set_destination(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
    ether.set_ethertype(EtherTypes::Arp);
    len += ether.packet_size();

    let mut arp = MutableArpPacket::new(ether.payload_mut()).unwrap();
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(source_mac);
    arp.set_sender_proto_addr(source_ip);
    arp.set_target_hw_addr(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
    arp.set_target_proto_addr(dest_ip);
    len += arp.packet_size();
    Some(len)
}
