use std::ptr;
use std::mem;
use std::net::Ipv4Addr;
use std::num::Wrapping;

static MSSTAB: [u16;4] = [ 1460, 1440, 1300, 536 ];
const COOKIEBITS: u32 = 24;	/* Upper bits store count */
const COOKIEMASK: u32 = ((1 << COOKIEBITS) - 1);
const SHA_WORKSPACE_WORDS: usize = 16;

const MAX_SYNCOOKIE_AGE: u32 = 2;


#[inline]
fn cookie_hash(source_addr: u32, dest_addr: u32, source_port: u16, dest_port: u16,
                count: u32, c: u32) -> u32 {
    let mut tmp: [u32; 16 + 5 + SHA_WORKSPACE_WORDS] = unsafe { mem::uninitialized() };

    ::RoutingTable::with_host_config(Ipv4Addr::from(dest_addr.to_be()) /* to_be? */, |hc| {
            tmp[4..4+17].copy_from_slice(&hc.syncookie_secret[c as usize][0..16]);
    });
    tmp[0] = source_addr;
    tmp[1] = dest_addr;
    tmp[2] = ((source_port as u32) << 16) + dest_port as u32;
    tmp[3] = count;
    unsafe {
        //::sha1::sha1_transform_ssse3(tmp.as_mut_ptr().offset(16), tmp.as_ptr() as *const u8, 1);
        ::sha1::sha1_transform_avx(tmp.as_mut_ptr().offset(16), tmp.as_ptr() as *const u8, 1);
        //::sha1::sha_transform(tmp.as_mut_ptr().offset(16), tmp.as_ptr() as *const u8, tmp.as_mut_ptr().offset(16 + 5));
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
    (Wrapping(cookie_hash(source_addr, dest_addr, source_port, dest_port, 0, 0))
            + Wrapping(sseq) + Wrapping(tcp_cookie_time << COOKIEBITS)
            + ((Wrapping(cookie_hash(source_addr, dest_addr, source_port, dest_port, tcp_cookie_time, 1)) + Wrapping(data)) & Wrapping(COOKIEMASK))).0
}

#[inline]
fn oct_to_u32(octets: [u8; 4]) -> u32 {
    (octets[0] as u32) << 24 | (octets[1] as u32) << 16 | (octets[2] as u32) << 8 | octets[3] as u32
}

/// Return cookie and mss value
#[inline]
pub fn generate_cookie_init_sequence(source_addr: Ipv4Addr, dest_addr: Ipv4Addr,
                                     source_port: u16, dest_port: u16,
                                     seq: u32, mss: u16, tcp_cookie_time: u32) -> (u32,u16) {
    let mut mssind = 3;
    let mut mssval = 1460;

    for (idx, val) in MSSTAB.iter().enumerate() {
        if mss >= *val {
            mssind = (MSSTAB.len() - idx - 1) as u32;
            mssval = *val;
            break;
        }
    }
    let source_octets = source_addr.octets();
    let dest_octets = dest_addr.octets();
    let cookie = secure_tcp_syn_cookie(oct_to_u32(source_octets).to_be(), oct_to_u32(dest_octets).to_be(),
                                     source_port.to_be(), dest_port.to_be(), seq, mssind, tcp_cookie_time);
    (cookie, mssval)
}

#[inline]
fn check_tcp_syn_cookie(cookie: u32, saddr: u32, daddr: u32,
                        sport: u16, dport: u16, sseq: u32) -> u32 {
    let diff: Wrapping<u32>;
    let mut count: Wrapping<u32> = Wrapping(0);

    ::RoutingTable::with_host_config(Ipv4Addr::from(daddr.to_be()) /* to_be? */, |hc| {
        count = Wrapping(hc.tcp_cookie_time as u32);
    });

    let mut cookie = Wrapping(cookie);
    /* Strip away the layers from the cookie */
    cookie -= Wrapping(cookie_hash(saddr, daddr, sport, dport, 0, 0)) + Wrapping(sseq);

    /* Cookie is now reduced to (count * 2^24) ^ (hash % 2^24) */
    diff = (count - (cookie >> COOKIEBITS as usize)) & Wrapping(0xffffffff >> COOKIEBITS);
    if diff >= Wrapping(MAX_SYNCOOKIE_AGE) {
        let cookie_time = cookie >> COOKIEBITS as usize;
        //println!("COOKIE TOO OLD: {} NOW: {} COOKIE: {}", diff, count, cookie_time);
        return 0xffffffff;
    }
    ((cookie - Wrapping(cookie_hash(saddr, daddr, sport, dport, (count - diff).0, 1))) & Wrapping(COOKIEMASK)).0
}

#[inline]
pub fn cookie_check(source_addr: Ipv4Addr, dest_addr: Ipv4Addr,
                    source_port: u16, dest_port: u16, seq: u32,
                    cookie: u32) -> Option<&'static u16> {
    let seq = seq - 1;
    let source_octets = source_addr.octets();
    let dest_octets = dest_addr.octets();
    let mssind = check_tcp_syn_cookie(cookie, oct_to_u32(source_octets).to_be(),
                        oct_to_u32(dest_octets).to_be(), source_port.to_be(),
                        dest_port.to_be(), seq);
    if mssind > 3 {
        //println!("COOKIE MSS IDX: {}", mssind);
    }
    MSSTAB.get(MSSTAB.len() - (mssind as usize) - 1)
}

/*
#[test]
fn test_cookie_init() {
    use ::pnet::util::MacAddr;
    let tcp_cookie_time = 0;
    let source_addr = Ipv4Addr::new(192, 168, 3, 237);
    let dest_addr = Ipv4Addr::new(192, 168, 111, 51);
    let source_port = 51771;
    let dest_port = 9000;
    let seq: u32 = 1646691064;
    let mss = 1460;
    ::RoutingTable::add_host(Ipv4Addr::new(192, 168, 111, 51), MacAddr::new(0, 0, 0, 0, 0, 0));
    ::RoutingTable::sync_tables();
    let (cookie, mss) = generate_cookie_init_sequence(source_addr, dest_addr, source_port, dest_port, seq.to_be(), mss, tcp_cookie_time);

    println!("COOKIE: {:?}", (cookie, mss));
    let mss = cookie_check(source_addr, dest_addr, source_port, dest_port, seq + 1, cookie);
    println!("CHECK COOKIE: {:?}", mss);
}
*/

#[inline]
pub fn synproxy_init_timestamp_cookie(wscale: u8, sperm: u8, ecn: u8, tcp_time_stamp: u32) -> u32 {
    let mut tsval: u32 = tcp_time_stamp & !0x3f;

    if wscale != 0 {
        tsval |= wscale as u32;
    } else {
        tsval |= 0xf;
    }

    if sperm != 0 {
        tsval |= 1 << 4;
    }

    if ecn != 0 {
        tsval |= 1 << 5;
    }

    tsval
}

