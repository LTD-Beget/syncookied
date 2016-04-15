extern crate netmap_sys;

use ::libc;
use std::mem;
use std::ptr;
use std::slice;
use std::ffi::CString;
use self::netmap_sys::netmap;
use self::netmap_sys::netmap_user;

#[allow(dead_code)]
#[derive(Debug)]
pub enum Action {
    Drop,
    Forward,
    Reply
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

pub struct NetmapSlot(netmap::netmap_slot);

impl NetmapSlot {
    fn get_buf_mut<'b,'a>(&'a mut self, ring: &NetmapRing) -> &'b mut [u8] {
        let buf_idx = self.0.buf_idx;
        let buf = unsafe { netmap_user::NETMAP_BUF(mem::transmute(ring), buf_idx as isize) as *mut u8 };
        unsafe { slice::from_raw_parts_mut::<u8>(buf, self.0.len as usize) }
    }

    fn get_buf<'b,'a>(&'a self, ring: &NetmapRing) -> &'b [u8] {
        let buf_idx = self.0.buf_idx;
        let buf = unsafe { netmap_user::NETMAP_BUF(mem::transmute(ring), buf_idx as isize) as *const u8 };
        unsafe { slice::from_raw_parts::<u8>(buf, self.0.len as usize) }
    }

    fn get_len(&self) -> u16 {
        self.0.len
    }

    fn set_len(&mut self, len: u16) {
        self.0.len = len;
    }

    fn set_flags(&mut self, flag: u16) {
        self.0.flags |= flag;
    }
}

pub struct NetmapRing(netmap::netmap_ring);

impl NetmapRing {
    pub fn is_empty(&self) -> bool {
        self.0.cur == self.0.tail
    }

    pub fn get_slot_mut<'a,'b>(&'a self) -> &'b mut NetmapSlot {
        let cur = self.0.cur;
        let slots = &self.0.slot as *const netmap::netmap_slot;
        unsafe { mem::transmute(slots.offset(cur as isize)) }
    }

    pub fn get_slot<'a,'b>(&'a self) -> &'b NetmapSlot {
        let cur = self.0.cur;
        let slots = &self.0.slot as *const netmap::netmap_slot;
        unsafe { mem::transmute(slots.offset(cur as isize)) }
    }

    pub fn set_flags(&mut self, flag: u32) {
        self.0.flags |= flag;
    }

    pub fn next_slot(&mut self) {
        self.0.cur = if self.0.cur + 1 == self.0.num_slots { 0 } else { self.0.cur + 1 };
        self.0.head = self.0.cur;
    }
}

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

    fn find_free_tx_ring(&self) -> Option<&mut NetmapRing> {
        let nifp = unsafe { (*self.raw).nifp };
        let mut tx_ring: *mut netmap::netmap_ring;
        let (first, last) = self.get_tx_rings();

        for ring in first..last+1 {
            tx_ring = unsafe { netmap_user::NETMAP_TXRING(nifp, ring as isize) };
            if unsafe { netmap::nm_ring_empty(tx_ring) } { // which means full for tx
                continue;
            }
            return Some(unsafe { mem::transmute(tx_ring) })
        }
        return None;
    }

    pub fn poll(&mut self, on_receive: fn(&[u8]) -> Action) {
        let fd = unsafe { (*self.raw).fd };
        let mut pollfd: libc::pollfd = unsafe { mem::zeroed() };
        let mut rx_ring: &mut NetmapRing;
        let nifp = unsafe { (*self.raw).nifp };

        pollfd.fd = fd;
        pollfd.events = libc::POLLIN;

        let rv = unsafe { libc::poll(&mut pollfd, 1, 1000) };

        let (first, last) = self.get_rx_rings();
        for ring in first..last+1 {
            rx_ring = unsafe { mem::transmute(netmap_user::NETMAP_RXRING(nifp, ring as isize)) };
            while !rx_ring.is_empty() {
                let mut rx_slot = rx_ring.get_slot_mut();
                let rx_slice = rx_slot.get_buf(rx_ring);
                match on_receive(rx_slice) {
                    Action::Drop => {},
                    Action::Forward => unsafe {
                            rx_slot.set_flags(netmap::NS_FORWARD as u16);
                            rx_ring.set_flags(netmap::NR_FORWARD as u32);
                    },
                    Action::Reply => {
                        // TODO
                        if let Some(tx_ring) = self.find_free_tx_ring() {
                            let tx_slot = tx_ring.get_slot_mut();
                            let tx_buf = tx_slot.get_buf_mut(tx_ring);
                            /* hack hack hack */
                            {
                                let len = ::reply(rx_slice, tx_buf);
                                tx_slot.set_flags(netmap::NS_BUF_CHANGED as u16 | netmap::NS_REPORT as u16);
                                tx_slot.set_len(len as u16);
                                tx_ring.next_slot();
                                println!("Sent reply len: {}", len);
                            }
                        }
                    }
                }
                rx_ring.next_slot();
            }
        }
    }
}
