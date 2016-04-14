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

pub struct NetmapDescriptor {
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

    pub fn poll(&mut self, on_receive: fn(&[u8]) -> Action) {
        let fd = unsafe { (*self.raw).fd };
        let mut pollfd: libc::pollfd = unsafe { mem::zeroed() };
        let mut rx_ring: *mut netmap::netmap_ring;
        let nifp = unsafe { (*self.raw).nifp };

        pollfd.fd = fd;
        pollfd.events = libc::POLLIN;

        let rv = unsafe { libc::poll(&mut pollfd, 1, 1000) };

        let (first, last) = self.get_rx_rings();
        for ring in first..last+1 {
            rx_ring = unsafe { netmap_user::NETMAP_RXRING(nifp, ring as isize) };
            if unsafe { netmap::nm_ring_empty(rx_ring) } {
                continue;
            }
            assert!(rx_ring != ptr::null_mut());
            {
                let rx_cur = unsafe { (*rx_ring).cur };
                let slots = unsafe { &(*rx_ring).slot as *const netmap::netmap_slot };
                let slot = unsafe { slots.offset(rx_cur as isize) as *mut netmap::netmap_slot };
                let buf_idx = unsafe { (*slot).buf_idx };
                let rx_len = unsafe { (*slot).len };
                let rx_buf = unsafe { netmap_user::NETMAP_BUF(rx_ring, buf_idx as isize) };
                let rx_slice = unsafe { slice::from_raw_parts::<u8>(rx_buf as *const u8, rx_len as usize) };
                match on_receive(rx_slice) {
                    Action::Drop => {},
                    Action::Forward => unsafe {
                            (*slot).flags |= netmap::NS_FORWARD as u16;
                            (*rx_ring).flags |= netmap::NR_FORWARD as u32;
                    },
                    Action::Reply => {
                        // TODO
                    }
                }
                unsafe {
                    (*rx_ring).cur = netmap_user::nm_ring_next(rx_ring, rx_cur);
                    (*rx_ring).head = (*rx_ring).cur;
                }
            }
        }
    }
}
