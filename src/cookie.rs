use std::ptr;
use std::mem;
use std::net::Ipv4Addr;

static msstab: [u16;4] = [ 536, 1300, 1440, 1460 ];
const COOKIEBITS: u32 = 24;	/* Upper bits store count */
const COOKIEMASK: u32 = ((1 << COOKIEBITS) - 1);

const SHA_WORKSPACE_WORDS: usize = 16;

#[inline]
fn cookie_hash(source_addr: u32, dest_addr: u32, source_port: u16, dest_port: u16,
                count: u32, c: u32) -> u32 {
    let mut tmp: [u32; 16 + 5 + SHA_WORKSPACE_WORDS] = unsafe { mem::uninitialized() };

    tmp[0] = source_addr;
    tmp[1] = dest_addr;
    tmp[2] = ((source_port as u32) << 16) + dest_port as u32;
    tmp[3] = count;
    unsafe {
        ptr::copy_nonoverlapping(::syncookie_secret[c as usize].as_ptr(), &mut tmp[4], 17);
        ::sha1::sha1_transform_ssse3(&mut tmp[16], mem::transmute(tmp.as_ptr()), 1);
    }

    tmp[17]
}

#[inline]
fn secure_tcp_syn_cookie(source_addr: u32, dest_addr: u32, source_port: u16, dest_port: u16, sseq: u32, data: u32, tcp_cookie_time: u32) -> u32 {
    /*
     * Compute the secure sequence number.
     * The output should be:
     *   HASH(sec1,saddr,sport,daddr,dport,sec1) + sseq + (count * 2^24)
     *      + (HASH(sec2,saddr,sport,daddr,dport,count,sec2) % 2^24).
     * Where sseq is their sequence number and count increases every
     * minute by 1.
     * As an extra hack, we add a small "data" value that encodes the
     * MSS into the second hash value.
     */
    cookie_hash(source_addr, dest_addr, source_port, dest_port, 0, 0)
            + sseq + (tcp_cookie_time << COOKIEBITS)
            + ((cookie_hash(source_addr, dest_addr, source_port, dest_port, tcp_cookie_time, 1) + data) & COOKIEMASK)
}

#[inline]
fn oct_to_u32(octets: [u8; 4]) -> u32 {
    (octets[0] as u32) << 24 | (octets[1] as u32) << 16 | (octets[2] as u32) << 8 | octets[3] as u32
}

#[inline]
pub fn generate_cookie_init_sequence(source_addr: Ipv4Addr, dest_addr: Ipv4Addr, source_port: u16, dest_port: u16, seq: u32, mss: u16, tcp_cookie_time: u32) -> u32 {
    /* TODO */
    let mssind = 3; /* 1460 */
    let source_octets = source_addr.octets();
    let dest_octets = dest_addr.octets();
    secure_tcp_syn_cookie(oct_to_u32(source_octets), oct_to_u32(dest_octets), source_port, dest_port, seq, mssind, tcp_cookie_time)
}


#[inline]
pub fn synproxy_init_timestamp_cookie(wscale: u8, sperm: u8, ecn: u8, tcp_time_stamp: u32) {
    let mut tsval: u32 = tcp_time_stamp & !0x3f;

    if wscale != 0 {
        tsval |= wscale;
    } else {
        tsval |= 0xf;
    }

    if sperm != 0 {
        tsval |= 1 << 4;
    }

    if ecn != 0 {
        tsval |= 1 << 5;
    }

    return tsval;
}

