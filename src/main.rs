#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate pnet;
extern crate crossbeam;
extern crate scheduler;
extern crate clap;

use std::thread;
use std::time::Duration;
use std::sync::mpsc;
use std::sync::atomic::{AtomicUsize, ATOMIC_USIZE_INIT};

use pnet::util::MacAddr;

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
use uptime::UptimeReader;
use packet::{IngressPacket};
use netmap::{Direction,NetmapDescriptor};

pub static TCP_TIME_STAMP: AtomicUsize = ATOMIC_USIZE_INIT;
pub static TCP_COOKIE_TIME: AtomicUsize = ATOMIC_USIZE_INIT;
pub static mut syncookie_secret: [[u32;17];2] = [[0;17];2];

pub enum OutgoingPacket {
    Ingress(IngressPacket),
    Forwarded((usize, usize)),
}

fn run(rx_iface: &str, tx_iface: &str, rx_mac: MacAddr, fwd_mac: MacAddr, uptime_reader: Box<UptimeReader>) {
    use std::sync::{Mutex,Arc};

    let rx_nm = Arc::new(Mutex::new(NetmapDescriptor::new(rx_iface).unwrap()));
    let tx_nm = if rx_iface == tx_iface {
         rx_nm.clone()
     } else {
         Arc::new(Mutex::new(NetmapDescriptor::new(tx_iface).unwrap()))
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
        scope.spawn(move|| loop {
            match uptime_reader.read() {
                Ok(buf) => uptime::update(buf),
                Err(err) => println!("Failed to read uptime: {:?}", err),
            }
            thread::sleep(one_sec);
        });

        for ring in 0..rx_count {
            let ring = ring;
            let (tx, rx) = mpsc::sync_channel(2 * 1024 * 1024);
            let pair = Arc::new(AtomicUsize::new(0));
            let rx_pair = pair.clone();

            let rx_nm = rx_nm.clone();

            scope.spawn(move || {
                println!("Starting RX thread for ring {} at {}", ring, rx_iface);
                let mut ring_nm = {
                    let nm = rx_nm.lock().unwrap();
                    nm.clone_ring(ring, Direction::Input).unwrap()
                };
                let cpu = ring as usize;
                rx::Receiver::new(ring, cpu, tx, &mut ring_nm, rx_pair, rx_mac.clone()).run();
            });

            let tx_nm = tx_nm.clone();
            scope.spawn(move || {
                println!("Starting TX thread for ring {} at {}", ring, tx_iface);
                let mut ring_nm = {
                    let nm = tx_nm.lock().unwrap();
                    nm.clone_ring(ring, Direction::Output).unwrap()
                };
                let cpu = /* rx_count as usize + */ ring as usize; /* HACK */
                tx::Sender::new(ring, cpu, rx, &mut ring_nm, pair, rx_mac.clone(), fwd_mac).run();
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
                               .arg(Arg::with_name("remote")
                                    .required_unless("local")
                                    .long("remote")
                                    .value_name("ip:port")
                                    .help("ip:port to get uptime from")
                                    .takes_value(true))
                               .arg(Arg::with_name("fwd-mac")
                                    .short("F")
                                    .required(true)
                                    .long("forward-to")
                                    .value_name("xx:xx:xx:xx:xx:xx")
                                    .help("Mac address we forward to")
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
        let fwd_mac = matches.value_of("fwd-mac").map(util::parse_mac).expect("Expected valid mac").unwrap();
        let local = matches.is_present("local");
        let ncpus = util::get_cpu_count();
        let uptime_reader: Box<UptimeReader> = if local {
            Box::new(uptime::LocalReader)
        } else {
            let addr = matches.value_of("remote").expect("Expected valid remote addr");
            Box::new(uptime::UdpReader::new(addr.to_owned()))
        };
        println!("interfaces: [Rx: {}/{}, Tx: {}] Fwd to: {} Cores: {} Local: {}", rx_iface, rx_mac, tx_iface, fwd_mac, ncpus, local);
        run(&rx_iface, &tx_iface, rx_mac, fwd_mac, uptime_reader);
    }
}
