use std::net::Ipv4Addr;

use pnet::packet::Packet;
use pnet::packet::ip::{IpNextHeaderProtocol};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;

#[link(name = "asm")]
extern "C" {
    fn csum_partial_folded(buff: *const u8, len: u32, wsum: u32) -> u16;
    fn ip_compute_csum(buff: *const u8, len: u32) -> u16;
}

#[inline]
pub fn tcp_checksum(packet: &TcpPacket, ipv4_source: Ipv4Addr,
                     ipv4_destination: Ipv4Addr,
                     next_level_protocol: IpNextHeaderProtocol) -> u16 {
    let IpNextHeaderProtocol(next_level_protocol) = next_level_protocol;
    let mut sum = 0u32;
    let octets = ipv4_source.octets();
    sum += ((octets[0] as u16) << 8 | (octets[1] as u16)) as u32;
    sum += ((octets[2] as u16) << 8 | (octets[3] as u16)) as u32;

    let octets = ipv4_destination.octets();
    sum += ((octets[0] as u16) << 8 | (octets[1] as u16)) as u32;
    sum += ((octets[2] as u16) << 8 | (octets[3] as u16)) as u32;

    sum += next_level_protocol as u32;
    let bytes = packet.packet();
    let len = bytes.len();
    sum += len as u32;
    unsafe { csum_partial_folded(bytes.as_ptr(), len as u32, sum.to_be()) }
}

pub fn ip_checksum(packet: &Ipv4Packet) -> u16 {
    use pnet::packet::Packet;

    let len = packet.get_header_length() as usize * 4;
    let bytes = packet.packet();

    unsafe { ip_compute_csum(bytes.as_ptr(), len as u32) }
}
