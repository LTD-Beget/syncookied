/// Utility functions
use std::path::{PathBuf};
use std::fs::{File,OpenOptions};
use std::io::{self,Write,Read};
use std::net::{SocketAddr,ToSocketAddrs};
use ::libc;
use ::url::Url;
use ::uptime::Protocol;

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

pub fn parse_addr(s: &str) -> io::Result<(Protocol,SocketAddr)> {
    let mut proto = Protocol::Udp;

    let sa = try!(match Url::parse(s) {
        Ok(url) => {
            proto = match url.scheme() {
                "udp" => Protocol::Udp,
                "tcp" => Protocol::Tcp,
                _ => panic!("unknown protocol"),
            };
            url.with_default_port(|_| Err(())).and_then(|hp| hp.to_socket_addrs().map(|mut sa| sa.next()))
        },
        Err(_) => {
            warn!("Deprecated syntax: use `udp://{}` instead", s);
            s.to_socket_addrs().map(|mut sa| sa.next())
        },
    }).unwrap();
    Ok((proto, sa))
}

#[test]
fn test_parse_addr() {
    use std::net::{IpAddr,Ipv4Addr};
    let addr = IpAddr::V4(Ipv4Addr::new(127,0,0,1));
    // new syntax, udp
    {
        let addr1 = parse_addr("udp://127.0.0.1:1488").unwrap();
        assert_eq!(addr1.0, Protocol::Udp);
        assert_eq!(addr1.1, SocketAddr::new(addr, 1488));
    }

    // old syntax (no proto, defaults to udp)
    {
        let addr1 = parse_addr("127.0.0.1:1488").unwrap();
        assert_eq!(addr1.0, Protocol::Udp);
        assert_eq!(addr1.1, SocketAddr::new(addr, 1488));
    }

    // new syntax, tcp
    {
        let addr1 = parse_addr("tcp://127.0.0.1:1488").unwrap();
        assert_eq!(addr1.0, Protocol::Tcp);
        assert_eq!(addr1.1, SocketAddr::new(addr, 1488));
    }

}

