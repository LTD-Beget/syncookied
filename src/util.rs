/// Utility functions
use std::path::{PathBuf};
use std::fs::{File,OpenOptions};
use std::io::{self,Write,Read};
use std::num::ParseIntError;
use ::libc;
use ::pnet::util::MacAddr;

use ::scheduler;
#[cfg(target_os = "linux")]
use ::scheduler::{CpuSet, Policy};

#[cfg(target_os = "linux")]
pub fn set_thread_name(name: &str) {
    let tid = unsafe { libc::syscall(186 /* gettid on x86_64 */) }; /* FIXME */
    let mut file = OpenOptions::new()
                    .write(true)
                    .create(false)
                    .open(format!("/proc/self/task/{}/comm", tid)).unwrap();
    file.write_all(name.as_bytes()).ok();
}

#[cfg(not(target_os = "linux"))]
pub fn set_thread_name(_: &str) {
   // todo: use setproctitle() on bsd
}

/// enable/disable syncookies on linux
pub fn set_syncookies(val: u8) -> Result<(), io::Error> {
    match OpenOptions::new()
        .write(true)
        .create(false)
        .open("/proc/sys/net/ipv4/tcp_syncookies")
    {
        Ok(mut file) => file.write_all(format!("{}", val).as_bytes()),
        Err(e) => Err(e),
    }
}

pub fn get_cpu_count() -> usize {
    unsafe {
        libc::sysconf(libc::_SC_NPROCESSORS_ONLN) as usize
    }
}

pub fn get_iface_mac(iface: &str) -> Result<String, io::Error> {
    let mut path = PathBuf::from("/sys/class/net/");
    path.push(iface);
    path.push("address");
    let mut file = try!(File::open(path));
    let mut buf = String::new();
    match file.read_to_string(&mut buf) {
        Ok(_) => Ok(buf.trim().to_owned()),
        Err(e) => Err(e),
    }
}

pub fn get_host_name() -> Option<String> {
    use std::ffi::CString;
    const HOST_NAME_MAX: usize = 256; /* XXX: add into libc */
    let mut buf = vec!(0; HOST_NAME_MAX + 1);
    let rv = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, HOST_NAME_MAX + 1) };
    if rv != 0 {
        None
    } else {
        let cstr = unsafe { CString::from_vec_unchecked(buf) };
        Some(cstr.into_string().unwrap())
    }
}

#[cfg(target_os = "linux")]
pub fn set_cpu_prio(cpu: usize, prio: i32) {
    scheduler::set_self_affinity(CpuSet::single(cpu)).expect("setting affinity failed");
    scheduler::set_self_policy(Policy::Fifo, prio).expect("setting sched policy failed");
}

// not currently supported in rust-scheduler
#[cfg(not(target_os = "linux"))]
pub fn set_cpu_prio(cpu: usize, prio: i32) {
    println!("Cpu binding and scheduling prio not implemented");
}
