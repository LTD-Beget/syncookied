/// Wraps `netmap_sys` with some (unsafe) iterators
extern crate netmap_sys;

use ::libc;
use std::mem;
use std::ptr;
use std::slice;
use std::iter::Iterator;
use std::ffi::{CStr,CString};
use self::netmap_sys::netmap;
use self::netmap_sys::netmap_user;

/// Forward slot
pub use self::netmap_sys::netmap::NS_FORWARD;

/// Indicate that buffer was changed
pub use self::netmap_sys::netmap::NS_BUF_CHANGED;

/// Report when sent
pub use self::netmap_sys::netmap::NS_REPORT;

/// Enable forwarding on ring
pub use self::netmap_sys::netmap::NR_FORWARD;

#[derive(Debug)]
#[allow(dead_code)]
pub enum Direction {
    Input,
    Output,
    InputOutput
}

#[derive(Debug)]
pub struct NetmapError {
    msg: String,
}

impl NetmapError {
    fn new(msg: String) -> Self {
        NetmapError { msg: msg }
    }
}

pub trait NetmapSlot {
    fn get_len(&self) -> u16;
    fn get_flags(&self) -> u16;
    fn set_flags(&mut self, flag: u16);
    fn get_buf_idx(&self) -> u32;
    fn set_buf_idx(&mut self, idx: u32);
}

pub struct RxSlot(netmap::netmap_slot);

impl NetmapSlot for RxSlot {
    fn get_len(&self) -> u16 {
        self.0.len
    }

    fn set_flags(&mut self, flag: u16) {
        self.0.flags |= flag;
    }

    fn get_flags(&self) -> u16 {
        self.0.flags
    }

    fn get_buf_idx(&self) -> u32 {
        self.0.buf_idx
    }

    fn set_buf_idx(&mut self, idx: u32) {
        self.0.buf_idx = idx
    }
}

impl RxSlot {
    #[inline]
    pub fn get_buf<'b,'a>(&'a self, ring: &RxRing) -> &'b [u8] {
        let buf_idx = self.0.buf_idx;
        let buf = unsafe { netmap_user::NETMAP_BUF(mem::transmute(ring), buf_idx as isize) as *const u8 };
        unsafe { slice::from_raw_parts::<u8>(buf, self.0.len as usize) }
    }
}

pub struct TxSlot(netmap::netmap_slot);

impl NetmapSlot for TxSlot {
    #[inline]
    fn get_len(&self) -> u16 {
        self.0.len
    }

    #[inline]
    fn set_flags(&mut self, flag: u16) {
        self.0.flags = flag;
    }

    #[inline]
    fn get_flags(&self) -> u16 {
        self.0.flags
    }

    #[inline]
    fn get_buf_idx(&self) -> u32 {
        self.0.buf_idx
    }

    #[inline]
    fn set_buf_idx(&mut self, idx: u32) {
        self.0.buf_idx = idx
    }
}

impl TxSlot {
    #[inline]
    pub fn get_buf_mut<'b,'a>(&'a mut self, ring: &TxRing) -> &'b mut [u8] {
        let buf_idx = self.0.buf_idx;
        let buf = unsafe { netmap_user::NETMAP_BUF(mem::transmute(ring), buf_idx as isize) as *mut u8 };
        unsafe { slice::from_raw_parts_mut::<u8>(buf, self.0.len as usize) }
    }

    #[inline]
    pub fn set_len(&mut self, len: u16) {
        self.0.len = len;
    }
}

pub trait NetmapRing {
    fn id(&self) -> u16;
    fn is_empty(&self) -> bool;
    fn next_slot(&mut self);
    fn set_flags(&mut self, flag: u32);
}

pub struct RxRing(netmap::netmap_ring);

impl RxRing {
    #[allow(dead_code)]
    #[inline]
    pub fn get_slot_mut<'a,'b>(&'a self) -> &'b mut RxSlot {
        let cur = self.0.cur;
        let slots = &self.0.slot as *const netmap::netmap_slot;
        unsafe { mem::transmute(slots.offset(cur as isize)) }
    }

    #[inline]
    pub fn iter(&mut self) -> RxSlotIter {
        let cur = self.0.cur;
        RxSlotIter {
            ring: self,
            cur: cur,
        }
    }
}

impl NetmapRing for RxRing {
    #[inline]
    fn id(&self) -> u16 {
        self.0.ringid
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.0.cur == self.0.tail
    }

    #[inline]
    fn set_flags(&mut self, flag: u32) {
        self.0.flags |= flag;
    }

    #[inline]
    fn next_slot(&mut self) {
        self.0.cur = if self.0.cur + 1 == self.0.num_slots { 0 } else { self.0.cur + 1 };
        self.0.head = self.0.cur;
    }
}

pub struct RxSlotIter<'a> {
    ring: &'a mut RxRing,
    cur: u32,
}

impl<'a> Iterator for RxSlotIter<'a> {
    type Item = (&'a mut RxSlot, &'a [u8]);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.ring.0.cur = self.cur;

        if self.ring.is_empty() {
            return None;
        }
        let cur = self.cur;
        let slots = self.ring.0.slot.as_mut_ptr();
        let slot: &mut RxSlot = unsafe { mem::transmute(slots.offset(cur as isize)) };
        let buf = slot.get_buf(self.ring);
        self.cur = if self.cur + 1 == self.ring.0.num_slots { 0 } else { self.cur + 1 };
        Some((slot, buf))
    }
}

impl<'a> Drop for RxSlotIter<'a> {
    fn drop(&mut self) {
        self.ring.0.cur = self.cur;
        self.ring.0.head = self.ring.0.cur;
    }
}

pub struct RxRingIter<'d> {
    cur: u16,
    last: u16,
    netmap: &'d NetmapDescriptor,
}

impl<'d> Iterator for RxRingIter<'d> {
    type Item = &'d mut RxRing;

    #[inline]
    fn next<'a>(&'a mut self) -> Option<&'d mut RxRing> {
        if self.cur > self.last {
            return None;
        }
        let rx_ring = {
            let cur = self.cur.clone();
            self.netmap.get_rx_ring(cur)
        };
        self.cur += 1;
        Some(rx_ring)
    }
}

pub struct TxRing(netmap::netmap_ring);

impl TxRing {
    #[inline]
    pub fn get_slot_mut<'a,'b>(&'a self) -> &'b mut TxSlot {
        let cur = self.0.cur;
        let slots = &self.0.slot as *const netmap::netmap_slot;
        unsafe { mem::transmute(slots.offset(cur as isize)) }
    }

    #[inline]
    pub fn iter(&mut self) -> TxSlotIter {
        let cur = self.0.head;
        TxSlotIter {
            ring: self,
            cur: cur,
        }
    }
}

impl NetmapRing for TxRing {
    #[inline]
    fn id(&self) -> u16 {
        self.0.ringid
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.0.cur == self.0.tail
    }

    #[inline]
    fn set_flags(&mut self, flag: u32) {
        self.0.flags |= flag;
    }

    #[inline]
    fn next_slot(&mut self) {
        self.0.cur = if self.0.cur + 1 == self.0.num_slots { 0 } else { self.0.cur + 1 };
        self.0.head = self.0.cur;
    }
}

impl<'a> Iterator for &'a mut TxRing {
    type Item = &'a mut TxSlot;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.0.cur;
        let slots = &self.0.slot as *const netmap::netmap_slot;
        let slot = unsafe { mem::transmute(slots.offset(cur as isize)) };
        self.next_slot();
        slot
    }
}

pub struct TxRingIter<'d> {
    last: u16,
    cur: u16,
    netmap: &'d NetmapDescriptor,
}

impl<'d> Iterator for TxRingIter<'d> {
    type Item = &'d mut TxRing;

    #[inline]
    fn next<'a>(&'a mut self) -> Option<&'d mut TxRing> {
        if self.cur > self.last {
            return None;
        }
        let tx_ring = {
            let cur = self.cur;
            self.netmap.get_tx_ring(cur)
        };
        self.cur += 1;
        Some(tx_ring)
    }
}

/// Slot and buffer iterator
pub struct TxSlotIter<'a> {
    ring: &'a mut TxRing,
    cur: u32
}

impl<'a> Iterator for TxSlotIter<'a> {
    type Item = (&'a mut TxSlot, &'a mut [u8]);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.ring.0.cur = self.cur;

        if self.ring.is_empty() {
            return None;
        }
        let cur = self.cur;
        let slots = self.ring.0.slot.as_mut_ptr();
        let slot: &mut TxSlot = unsafe { mem::transmute(slots.offset(cur as isize)) };
        slot.set_len(2048);
        let buf = slot.get_buf_mut(self.ring);
        self.cur = if self.cur + 1 == self.ring.0.num_slots { 0 } else { self.cur + 1 };
        Some((slot, buf))
    }
}

impl<'a> Drop for TxSlotIter<'a> {
    fn drop(&mut self) {
        self.ring.0.cur = self.cur;
        self.ring.0.head = self.ring.0.cur;
    }
}

/// Netmap descriptor wrapper
pub struct NetmapDescriptor {
    raw: *mut netmap_user::nm_desc
}

unsafe impl Send for NetmapDescriptor {}

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

    pub fn new_with_memory(iface: &str, parent: &NetmapDescriptor) -> Result<Self, NetmapError> {
        let base_nmd: netmap::nmreq = unsafe { mem::zeroed() };
        let netmap_iface = CString::new(format!("netmap:{}", iface)).unwrap();

        let netmap_desc = unsafe { netmap_user::nm_open(netmap_iface.as_ptr(), &base_nmd, netmap_user::NM_OPEN_NO_MMAP as u64, parent.raw) };
        if netmap_desc == ptr::null_mut() {
            return Err(NetmapError::new(format!("Can't open {:?}", netmap_iface)));
        }
        Ok(NetmapDescriptor {
            raw: netmap_desc
        })
    }

    pub fn get_ifname(&self) -> String {
        const IFNAMSIZ: usize = libc::IF_NAMESIZE;
        unsafe {
            let nifp = (*self.raw).nifp;
            let mut buf = vec![0;IFNAMSIZ + 1];
            libc::strncpy(buf.as_mut_ptr() as *mut libc::c_char, (*nifp).ni_name.as_ptr(), IFNAMSIZ);
            let cstr = CString::from_vec_unchecked(buf);
            cstr.into_string().unwrap()
        }
    }

    pub fn rx_iter<'i, 'd: 'i>(&'d mut self) -> RxRingIter<'i> {
        let (first, last) = self.get_rx_rings();

        RxRingIter {
            last: last,
            cur: first,
            netmap: self,
        }
    }

    pub fn tx_iter<'i, 'd: 'i>(&'d mut self) -> TxRingIter<'i> {
        let (first, last) = self.get_tx_rings();

        TxRingIter {
            last: last,
            cur: first,
            netmap: self,
        }
    }

    pub fn clone_ring(&self, ring: u16, dir: Direction) -> Result<Self,NetmapError> {
        let mut nm_desc_raw: netmap_user::nm_desc = unsafe { (*(self.raw)) };

        /* XXX: check that we opened it with ALL_NIC before */
        let (flag, ring_flag) = match dir {
            Direction::Input => (netmap::NR_RX_RINGS_ONLY, netmap::NETMAP_NO_TX_POLL),
            Direction::Output => (netmap::NR_TX_RINGS_ONLY, 0),
            Direction::InputOutput => (0, 0),
        };
        nm_desc_raw.req.nr_flags = netmap::NR_REG_ONE_NIC as u32 | flag as u32;
        if ring == self.get_rx_rings_count() { nm_desc_raw.req.nr_flags = netmap::NR_REG_SW as u32 | flag };
        nm_desc_raw.req.nr_ringid = ring | ring_flag as u16;
        nm_desc_raw.self_ = &mut nm_desc_raw;

        let ifname = unsafe { CStr::from_ptr(nm_desc_raw.req.nr_name.as_ptr()).to_str().unwrap() };
        let netmap_ifname = CString::new(format!("netmap:{}", ifname)).unwrap();

        let netmap_desc = unsafe {
            netmap_user::nm_open(netmap_ifname.as_ptr(),
                                 ptr::null(),
                                 netmap_user::NM_OPEN_NO_MMAP as u64 | netmap_user::NM_OPEN_IFNAME as u64 /* | flag as u64 */,
                                 &nm_desc_raw)
        };
        if netmap_desc == ptr::null_mut() {
            return Err(NetmapError::new(format!("Can't open ring {}", ring)));
        }
        Ok(NetmapDescriptor {
            raw: netmap_desc
        })
    }

    pub fn get_rx_rings_count(&self) -> u16 {
        let nifp = unsafe { (*self.raw).nifp };
        unsafe { (*nifp).ni_rx_rings as u16 }
    }

    pub fn get_tx_rings_count(&self) -> u16 {
        let nifp = unsafe { (*self.raw).nifp };
        unsafe { (*nifp).ni_tx_rings as u16 }
    }

    #[allow(dead_code)]
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

    #[inline]
    fn get_tx_ring(&self, ring: u16) -> &mut TxRing {
        let nifp = unsafe { (*self.raw).nifp };

        unsafe { mem::transmute(netmap_user::NETMAP_TXRING(nifp, ring as isize)) }
    }

    #[inline]
    fn get_rx_ring(&self, ring: u16) -> &mut RxRing {
        let nifp = unsafe { (*self.raw).nifp };

        unsafe { mem::transmute(netmap_user::NETMAP_RXRING(nifp, ring as isize)) }
    }

    #[allow(dead_code)]
    fn find_free_tx_ring(&self) -> Option<&mut TxRing> {
        let (first, last) = self.get_tx_rings();

        for ring in first..last+1 {
            let tx_ring = self.get_tx_ring(ring);
            if !tx_ring.is_empty() {
                return Some(tx_ring);
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn get_fd(&self) -> i32 {
        unsafe { (*self.raw).fd }
    }

    /*
    #[allow(dead_code)]
    pub fn tx_sync(fd: i32) {
        unsafe { libc::ioctl(fd, netmap::NIOCTXSYNC as u64) };
    }

    #[allow(dead_code)]
    pub fn rx_sync(fd: i32) {
        unsafe { libc::ioctl(fd, netmap::NIOCRXSYNC as u64) };
    }
    */

    pub fn poll(&mut self, dir: Direction) -> Option<()> {
        let fd = unsafe { (*self.raw).fd };
        let mut pollfd: libc::pollfd = unsafe { mem::zeroed() };

        pollfd.fd = fd;
        pollfd.events = match dir {
            Direction::Input => libc::POLLIN,
            Direction::Output => libc::POLLOUT,
            Direction::InputOutput => libc::POLLIN | libc::POLLOUT,
        };

        let rv = unsafe { libc::poll(&mut pollfd, 1, 1000) };
        if rv <= 0 {
            return None;
        }
        if pollfd.revents & libc::POLLERR == libc::POLLERR {
            error!("POLLERR!");
            return None;
        }
        Some(())
    }
}
