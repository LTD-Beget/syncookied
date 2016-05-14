use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};

pub trait UptimeReader: Send {
    fn read(&self) -> Vec<u8>;
}

pub struct LocalReader;

impl UptimeReader for LocalReader {
    fn read(&self) -> Vec<u8> {
        use std::fs::File;
        use std::io::prelude::*;
        let mut file = File::open("/proc/beget_uptime").unwrap();
        let mut buf = vec![];
        file.read_to_end(&mut buf);
        buf
    }
}

pub struct UdpReader {
    addr: String,
}

impl UdpReader {
    pub fn new(addr: String) -> Self {
        UdpReader {
            addr: addr 
        }
    }
}

impl UptimeReader for UdpReader {
    fn read(&self) -> Vec<u8> {
        use std::net::UdpSocket;

        let mut buf = vec![0;1024];
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        loop {
            socket.send_to(b"YO", self.addr.as_str());
            if let Ok((_,addr)) = socket.recv_from(&mut buf[0..]) {
                return buf;
            }
        }
    }
}

pub fn update(buf: Vec<u8>) {
    use std::io::prelude::*;
    use std::io::BufReader;

    let mut jiffies = 0;
    let mut tcp_cookie_time = 0;

    let reader = BufReader::new(&buf[..]);
    for (idx, line) in reader.lines().enumerate() {
        let line = line.unwrap();
        match idx {
            0 => {
                for (idx, word) in line.split(' ').enumerate() {
                    match idx {
                        0 => { jiffies = word.parse::<u64>().unwrap() },
                        1 => { tcp_cookie_time = word.parse::<u32>().unwrap() },
                        _ => {},
                    }
                }
            },
            1 => {
                for (idx, word) in line.split('.').enumerate() {
                    if word == "" {
                        continue;
                    }
                    unsafe { ::syncookie_secret[0][idx] = u32::from_str_radix(word, 16).unwrap() };
                }
            },
            2 => {
                for (idx, word) in line.split('.').enumerate() {
                    if word == "" {
                        continue;
                    }
                    unsafe { ::syncookie_secret[1][idx] = u32::from_str_radix(word, 16).unwrap() };
                }
            },
            _ => {},
        }
    }
    //println!("jiffies: {}, tcp_cookie_time: {}, syncookie_secret: {:?}", jiffies, tcp_cookie_time, unsafe { syncookie_secret });
    ::TCP_TIME_STAMP.store(jiffies as usize & 0xffffffff, Ordering::SeqCst);
    ::TCP_COOKIE_TIME.store(tcp_cookie_time as usize, Ordering::SeqCst);
}

pub fn run_server(addr: &str) {
    use std::net::UdpSocket;
    let mut socket = UdpSocket::bind(addr).expect("Cannot bind socket");

    loop {
        let mut buf = [0; 64];
        if let Ok((_,addr)) = socket.recv_from(&mut buf[0..]) {
            let buf = LocalReader.read();
            socket.send_to(&buf[..], addr);
        }
    }
}
