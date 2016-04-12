extern crate netmap_sys;
extern crate libc;
extern crate pnet;

use std::env;
use std::mem;
use std::ptr;
use std::process;
use std::slice;
use std::thread;
use std::ffi::CString;
use netmap_sys::netmap;
use netmap_sys::netmap_user;

use std::net::IpAddr;

use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::tcp::TcpPacket;

#[derive(Debug)]
enum Action {
    Drop,
    Forward,
}

// helpers
fn get_cpu_count() -> usize {
    unsafe { 
        libc::sysconf(libc::_SC_NPROCESSORS_ONLN) as usize
    } 
}

#[derive(Debug)]
struct NetmapError {
    msg: String,
}

impl NetmapError {
    fn new(msg: String) -> Self {
        NetmapError { msg: msg }
    }
}

struct NetmapDescriptor {
    raw: *mut netmap_user::nm_desc
}

impl NetmapDescriptor {
    pub fn new(iface: &str) -> Result<Self, NetmapError> {
        let base_nmd: netmap::nmreq = unsafe { mem::zeroed() };
        let netmap_iface = CString::new(format!("netmap:{}", iface)).unwrap();

        let netmap_desc = unsafe { netmap_user::nm_open(netmap_iface.as_ptr(), &base_nmd, 0, ptr::null()) };
        if netmap_desc == ptr::null_mut() {
            return Err(NetmapError::new(format!("Can't open {:?}", netmap_iface)));
        }
        Ok(NetmapDescriptor {
            raw: netmap_desc
        })
    }

    pub fn clone_ring(&self, ring: u16) -> Result<Self,NetmapError> {
        let mut nm_desc_raw = unsafe { (*self.raw).clone() };

        /* XXX: check that we opened it with ALL_NIC before */
        nm_desc_raw.req.nr_flags = netmap::NR_REG_ONE_NIC as u32;
        nm_desc_raw.req.nr_ringid = ring;

        let ifname = unsafe { CString::from_raw((*self.raw).req.nr_name.as_mut_ptr()).into_string().unwrap() };
        let netmap_ifname = CString::new(format!("netmap:{}", ifname)).unwrap();

        let netmap_desc = unsafe {
            netmap_user::nm_open(netmap_ifname.as_ptr(),
                                 ptr::null(),
                                 netmap_user::NM_OPEN_NO_MMAP as u64 | netmap_user::NM_OPEN_IFNAME as u64,
                                 self.raw)
        };
        if netmap_desc == ptr::null_mut() {
            return Err(NetmapError::new(format!("Can't open ring {}", ring)));
        }
        Ok(NetmapDescriptor {
            raw: netmap_desc
        })
    }

    pub fn get_rx_rings_count(&self) -> u16 {
        unsafe { (*self.raw).req.nr_rx_rings }
    }

    pub fn get_tx_rings_count(&self) -> u16 {
        unsafe { (*self.raw).req.nr_tx_rings }
    }

    pub fn get_flags(&self) -> u32 {
        unsafe { (*self.raw).req.nr_flags }
    }

    /// Returns first and last RX ring
    pub fn get_rx_rings(&self) -> (u16,u16) {
        unsafe { ((*self.raw).first_rx_ring, (*self.raw).last_rx_ring) }
    }

    pub fn get_tx_rings(&self) -> (u16,u16) {
        unsafe { ((*self.raw).first_tx_ring, (*self.raw).last_tx_ring) }
    }

    pub fn poll(&mut self, handler: fn(&[u8]) -> Action) {
        let fd = unsafe { (*self.raw).fd };
        let mut pollfd: libc::pollfd = unsafe { mem::zeroed() };
        let mut rx_ring: *mut netmap::netmap_ring = ptr::null_mut();
        let nifp = unsafe { (*self.raw).nifp };

        pollfd.fd = fd;
        pollfd.events = libc::POLLIN;

        println!("before poll");
        let rv = unsafe { libc::poll(&mut pollfd, 1, 1000) };
        println!("poll: {}", rv);

        let (first, last) = self.get_rx_rings();
        for ring in first..last+1 {
            println!("ring {}", ring);
            rx_ring = unsafe { netmap_user::NETMAP_RXRING(nifp, ring as isize) };
            if unsafe { netmap::nm_ring_empty(rx_ring) } {
                continue;
            }
            assert!(rx_ring != ptr::null_mut());
            {
                let rx_cur = unsafe { (*rx_ring).cur };
                let slots = unsafe { &(*rx_ring).slot as *const netmap::netmap_slot };
                let slot = unsafe { slots.offset(rx_cur as isize) };
                let buf_idx = unsafe { (*slot).buf_idx };
                let rx_len = unsafe { (*slot).len };
                let rx_buf = unsafe { netmap_user::NETMAP_BUF(rx_ring, buf_idx as isize) };
                let rx_slice = unsafe { slice::from_raw_parts::<u8>(rx_buf as *const u8, rx_len as usize) };
                match handler(rx_slice) {
                    Action::Drop => {},
                    Action::Forward => {}, // TODO
                }
                unsafe {
                    (*rx_ring).cur = netmap_user::nm_ring_next(rx_ring, rx_cur);
                    (*rx_ring).head = (*rx_ring).cur;
                }
            }
        }
    }
}

fn handle_udp_packet(source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        println!("UDP Packet: {}:{} > {}:{}; length: {}", source,
                        udp.get_source(), destination, udp.get_destination(), udp.get_length());
    } else {
        println!("Malformed UDP Packet");
    }
}

fn handle_tcp_packet(source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        //println!("TCP Packet: {}:{} > {}:{}; length: {}", source,
        //            tcp.get_source(), destination, tcp.get_destination(), packet.len());
        println!("TCP Packet: {:?}", tcp);
    } else {
        println!("Malformed TCP Packet");
    }
}

fn handle_transport_protocol(source: IpAddr, destination: IpAddr,
                             protocol: IpNextHeaderProtocol, packet: &[u8]) {
    match protocol {
        IpNextHeaderProtocols::Udp  => handle_udp_packet(source, destination, packet),
        IpNextHeaderProtocols::Tcp  => handle_tcp_packet(source, destination, packet),
        _ => println!("Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                match source { IpAddr::V4(..) => "IPv4", _ => "IPv6" },
                source,
                destination,
                protocol,
                packet.len())

    }
}

fn handle_ipv4_packet(ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(IpAddr::V4(header.get_source()),
                                  IpAddr::V4(header.get_destination()),
                                  header.get_next_level_protocol(),
                                  header.payload());
    } else {
        println!("Malformed IPv4 Packet");
    }
}

fn handle_packet(packet_data: &[u8]) -> Action {
    let eth = EthernetPacket::new(packet_data).unwrap();
    handle_ether_packet(&eth);
    Action::Drop
}

fn handle_ether_packet(ethernet: &EthernetPacket) {
    println!("{:?}", &ethernet);
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(ethernet),
        //EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet),
        //EtherTypes::Arp  => handle_arp_packet(interface_name, ethernet),
        _                => println!("Unknown packet: {} > {}; ethertype: {:?} length: {}",
                                        ethernet.get_source(),
                                        ethernet.get_destination(),
                                        ethernet.get_ethertype(),
                                        ethernet.packet().len())
    }
}

fn rx_loop(netmap: &mut NetmapDescriptor) {
        println!("Rx rings: {:?}", netmap.get_rx_rings());
        println!("Tx rings: {:?}", netmap.get_tx_rings());
        thread::sleep_ms(1000);
        for _ in (0..10) {
            netmap.poll(handle_packet);
        }
}

fn run(iface: &str) {
    let nm = NetmapDescriptor::new(iface).unwrap();
    println!("Rx rings: {}, Tx rings: {} flags: {}", nm.get_rx_rings_count(), nm.get_tx_rings_count(), nm.get_flags());

    for ring in 0..nm.get_rx_rings_count() {
        let mut ring_nm = nm.clone_ring(ring).unwrap();
        /* XXX */
        rx_loop(&mut ring_nm);
    }
}

fn main() {
    let iface = env::args().nth(1).unwrap();
    let ncpus = get_cpu_count();
    println!("interface: {} cores: {}", iface, ncpus);
    run(&iface);
}
