#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate pnet;
extern crate crossbeam;
extern crate scheduler;
extern crate clap;
extern crate yaml_rust;
extern crate parking_lot;
extern crate mpsc;
extern crate intmap;
extern crate fnv;
extern crate bounded_spsc_queue as spsc;

use std::fmt;
use std::cell::RefCell;
use std::thread;
use std::time::Duration;
use std::sync::atomic::{AtomicUsize};
use std::net::Ipv4Addr;
use std::str::FromStr;
use pnet::util::MacAddr;
use parking_lot::RwLock;
use intmap::LocklessIntMap;

use std::collections::BTreeMap;
use std::hash::BuildHasherDefault;

use clap::{Arg, App, AppSettings, SubCommand};

mod netmap;
mod cookie;
mod sha1;
mod packet;
mod csum;
mod util;
mod tx;
mod rx;
mod uptime;
mod arp;
mod config;
use uptime::UptimeReader;
use packet::{IngressPacket};
use netmap::{Direction,NetmapDescriptor};

lazy_static! {
    /* maps public IP to tcp parameters */
    static ref GLOBAL_HOST_CONFIGURATION: RwLock<BTreeMap<Ipv4Addr, HostConfiguration>> = {
        let hm = BTreeMap::new();
        RwLock::new(hm)
    };
}

thread_local!(pub static LOCAL_ROUTING_TABLE: RefCell<BTreeMap<Ipv4Addr, HostConfiguration>> = {
    let hm = BTreeMap::new();
    RefCell::new(hm)
});

#[derive(Clone)]
struct StateTable {
    map: LocklessIntMap<BuildHasherDefault<fnv::FnvHasher>>,
}

impl fmt::Debug for StateTable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "StateTable")
    }
}

impl StateTable {
    fn oct_to_u32(octets: [u8; 4]) -> u32 {
        (octets[0] as u32) << 24 | (octets[1] as u32) << 16 | (octets[2] as u32) << 8 | octets[3] as u32
    }

    fn new(size: usize) -> Self {
        StateTable {
            map: LocklessIntMap::new(1024 * 1024, BuildHasherDefault::<fnv::FnvHasher>::default())
        }
    }

    pub fn add_state(&mut self, ip: Ipv4Addr, source_port: u16, dest_port: u16, state: usize) {
        let key: usize = (Self::oct_to_u32(ip.octets()) as usize) << 32
                         | (source_port as usize) << 16
                         | dest_port as usize;
        self.map.insert(key, state);
    }
    
    pub fn get_state(&self, ip: Ipv4Addr, source_port: u16, dest_port: u16) -> Option<usize> {
        let key: usize = (Self::oct_to_u32(ip.octets()) as usize) << 32
                         | (source_port as usize) << 16
                         | dest_port as usize;
        self.map.get(key)
    }
}

pub struct RoutingTable;

impl RoutingTable {
    fn add_host(ip: Ipv4Addr, mac: MacAddr) {
        println!("Configuration: {} -> {}", ip, mac);
        let host_conf = HostConfiguration::new(mac);
        let mut w = GLOBAL_HOST_CONFIGURATION.write();

        w.insert(ip, host_conf);
    }

    pub fn get_ips() -> Vec<Ipv4Addr> {
        let r = GLOBAL_HOST_CONFIGURATION.read();
        r.keys().cloned().collect()
    }

    pub fn sync_tables() {
        LOCAL_ROUTING_TABLE.with(|rt| {
            let ips = ::RoutingTable::get_ips();
            let mut cache = rt.borrow_mut();
            for ip in ips.iter() {
                ::RoutingTable::with_host_config_global(*ip, |hc| { cache.insert(*ip, hc.to_owned()); });
            }
        })
    }

    pub fn with_host_config<F>(ip: Ipv4Addr, mut f: F) -> Option<()> where F: FnMut(&HostConfiguration) {
        LOCAL_ROUTING_TABLE.with(|rt| {
            let r = rt.borrow();
            if let Some(hc) = r.get(&ip) {
                f(hc);
                Some(())
            } else {
                println!("Config for {} not found", ip);
                None
            }
        })
    }

    pub fn with_host_config_global<F>(ip: Ipv4Addr, mut f: F) -> Option<()> where F: FnMut(&HostConfiguration) {
        let r = GLOBAL_HOST_CONFIGURATION.read();
        if let Some(hc) = r.get(&ip) {
            f(hc);
            Some(())
        } else {
            println!("Config for {} not found", ip);
            None
        }
    }

    pub fn with_host_config_mut<F>(ip: Ipv4Addr, mut f: F) -> Option<()> where F: FnMut(&mut HostConfiguration) {
        let mut w = GLOBAL_HOST_CONFIGURATION.write();
        if let Some(hc) = w.get_mut(&ip) {
            f(hc);
            Some(())
        } else {
            println!("Config for {} not found", ip);
            None
        }
    }
}

#[derive(Debug,Clone)]
pub struct HostConfiguration {
    mac: MacAddr,
    tcp_timestamp: u64,
    tcp_cookie_time: u64,
    syncookie_secret: [[u32;17];2],
    state_table: StateTable,
}

impl HostConfiguration {
    fn new(mac: MacAddr) -> Self {
        HostConfiguration {
            mac: mac,
            tcp_timestamp: 0,
            tcp_cookie_time: 0,
            syncookie_secret: [[0;17];2],
            state_table: StateTable::new(1024 * 1024),
        }
    }
}

pub enum OutgoingPacket {
    Ingress(IngressPacket),
    Forwarded((usize, usize, MacAddr)),
}

fn run(rx_iface: &str, tx_iface: &str, rx_mac: MacAddr, tx_mac: MacAddr, uptime_readers: Vec<(Ipv4Addr, Box<UptimeReader>)>) {
    use std::sync::{Mutex,Arc};

    let rx_nm = Arc::new(Mutex::new(NetmapDescriptor::new(rx_iface).unwrap()));
    let multi_if = rx_iface != tx_iface;
    let tx_nm = if multi_if {
         let rx_nm = &*rx_nm.lock().unwrap();
         Arc::new(Mutex::new(NetmapDescriptor::new_with_memory(tx_iface, rx_nm).unwrap()))
     } else {
         rx_nm.clone()
    };
    let rx_count = {
        let rx_nm = rx_nm.lock().unwrap();
        rx_nm.get_rx_rings_count()
    };
    let tx_count = {
        let tx_nm = tx_nm.lock().unwrap();
        tx_nm.get_tx_rings_count()
    };
    println!("{} Rx rings @ {}, {} Tx rings @ {}", rx_count, rx_iface, tx_count, tx_iface);
    if tx_count < rx_count {
        panic!("We need at least as much Tx rings as Rx rings")
    }

    crossbeam::scope(|scope| {
        let one_sec = Duration::new(1, 0);
        for (ip, uptime_reader) in uptime_readers.into_iter() {
            scope.spawn(move|| loop {
                match uptime_reader.read() {
                    Ok(buf) => uptime::update(ip, buf),
                    Err(err) => println!("Failed to read uptime: {:?}", err),
                }
                thread::sleep(one_sec);
            });
        }

        for ring in 0..rx_count {
            let ring = ring;
            let (tx, rx) = spsc::make(4 * 1024 * 1024);
            let (f_tx, f_rx) = spsc::make(4 * 1024 * 1024);
            let pair = Arc::new(AtomicUsize::new(0));
            let rx_pair = pair.clone();

            {
                let rx_nm = rx_nm.clone();

                scope.spawn(move || {
                    println!("Starting RX thread for ring {} at {}", ring, rx_iface);
                    let mut ring_nm = {
                        let nm = rx_nm.lock().unwrap();
                        nm.clone_ring(ring, Direction::Input).unwrap()
                    };
                    let cpu = ring as usize;
                    rx::Receiver::new(ring, cpu, f_tx, tx, &mut ring_nm, rx_pair, rx_mac.clone()).run();
                });
            }

            /* Start an ARP thread to keep switch from forgetting about us */
            /*
            if multi_if && ring == 0 {
                    let rx_nm = rx_nm.clone();

                    scope.spawn(move || {
                    println!("Starting ARP thread for ring {} at {}", ring, rx_iface);
                    let mut ring_nm = {
                        let nm = rx_nm.lock().unwrap();
                        nm.clone_ring(ring, Direction::Output).unwrap()
                    };
                    let cpu = ring as usize;
                    /* XXX: replace hardcoded IPs */
                    arp::Sender::new(ring, cpu, &mut ring_nm, rx_mac.clone(), Ipv4Addr::new(185,50,25,2), Ipv4Addr::new(185,50,25,1)).run();
                });
            }
            */

            /* second half */
            {
                let f_tx_nm = rx_nm.clone();
                let pair = pair.clone();
                scope.spawn(move || {
                    println!("Starting TX thread for ring {} at {}", ring, rx_iface);
                    let mut ring_nm = {
                        let nm = f_tx_nm.lock().unwrap();
                        nm.clone_ring(ring, Direction::Output).unwrap()
                    };
                    let cpu = ring as usize; /* HACK */
                    tx::Sender::new(ring, cpu, f_rx, &mut ring_nm, pair, rx_mac.clone()).run();
                });
            }


            let tx_nm = tx_nm.clone();
            scope.spawn(move || {
                println!("Starting TX thread for ring {} at {}", ring, tx_iface);
                let mut ring_nm = {
                    let nm = tx_nm.lock().unwrap();
                    nm.clone_ring(ring, Direction::Output).unwrap()
                };
                let cpu = rx_count as usize + ring as usize; /* HACK */
                tx::Sender::new(ring, cpu, rx, &mut ring_nm, pair, tx_mac).run();
            });
        }

        /*
        {
            let nm = rx_nm.clone();
            let ring = rx_count;

            scope.spawn(move || {
                    println!("Starting Host RX thread for ring {}", ring);
                    let mut ring_nm = {
                        let nm = nm.lock().unwrap();
                        nm.clone_ring(ring, Direction::Input).unwrap()
                    };
                    host_rx_loop(ring as usize, &mut ring_nm)
            });

        }
        */
    });
}

fn main() {
    let matches = App::new("syncookied")
                              .version("0.1")
                              .author("Alexander Polyakov <apolyakov@beget.ru>")
                              .setting(AppSettings::SubcommandsNegateReqs)
                              .subcommand(
                                SubCommand::with_name("server")
                                .about("Run /proc/beget_uptime reader")
                                .arg(Arg::with_name("addr")
                                     .takes_value(true)
                                     .value_name("ip:port")
                                     .help("ip:port to listen on"))
                              )
                              .arg(Arg::with_name("local")
                                   .long("local")
                                   .conflicts_with("remote")
                                   .help("Operate on a single host"))
                              .arg(Arg::with_name("in")
                                   .short("i")
                                   .long("input-interface")
                                   .value_name("iface")
                                   .help("Interface to receive packets on")
                                   .required(true)
                                   .takes_value(true))
                               .arg(Arg::with_name("out")
                                   .short("o")
                                   .long("output-interface")
                                   .value_name("iface")
                                   .help("Interface to send packets on (input interface will be used if not set)")
                                   .takes_value(true))
                               .arg(Arg::with_name("in-mac")
                                    .short("I")
                                    .required(true)
                                    .long("input-mac")
                                    .value_name("xx:xx:xx:xx:xx:xx")
                                    .help("Input interface mac address")
                                    .takes_value(true))
                               .arg(Arg::with_name("out-mac")
                                    .short("O")
                                    .required(false)
                                    .long("output-mac")
                                    .value_name("xx:xx:xx:xx:xx:xx")
                                    .help("Output interface mac address")
                                    .takes_value(true))
                               .get_matches();

    if let Some(matches) = matches.subcommand_matches("server") {
        let addr = matches.value_of("addr").unwrap_or("127.0.0.1:1488"); 
        println!("running server on {}", addr);
        uptime::run_server(addr);
    } else {
        let rx_iface = matches.value_of("in").expect("Expected valid input interface");
        let tx_iface = matches.value_of("out").unwrap_or(rx_iface);
        let rx_mac = matches.value_of("in-mac").map(util::parse_mac).expect("Expected valid mac").unwrap();
        let tx_mac: MacAddr = matches.value_of("out-mac").map(|mac| util::parse_mac(mac).expect("Expected valid mac")).unwrap_or(rx_mac.clone());
        let local = matches.is_present("local");
        let ncpus = util::get_cpu_count();

        let uptime_readers = if !local {
            config::configure().iter().map(|&(ip, ref addr)|
                (ip, Box::new(uptime::UdpReader::new(addr.to_owned())) as Box<UptimeReader>)
            ).collect()
        } else {
            vec![(Ipv4Addr::new(127,0,0,1), Box::new(uptime::LocalReader) as Box<UptimeReader>)]
        };

        println!("interfaces: [Rx: {}/{}, Tx: {}/{}] Cores: {} Local: {}", rx_iface, rx_mac, tx_iface, tx_mac, ncpus, local);
        run(&rx_iface, &tx_iface, rx_mac, tx_mac, uptime_readers);
    }
}
