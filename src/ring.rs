/// Ring thread
use std::time::{self,Duration};
use std::thread;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use ::netmap::{self, NetmapDescriptor, RxSlot, NetmapSlot, NetmapRing, RxRing, TxRing};
use ::pnet::packet::ethernet::MutableEthernetPacket;
use ::ForwardedPacket;
use ::packet::{self,IngressPacket};
use ::pnet::util::MacAddr;
use ::util;
use ::libc;
use ::spsc;
use ::packet::{Action,Reason};
use ::metrics;
use ::parking_lot::{Mutex,Condvar};

#[derive(Debug,Default)]
struct RxStats {
    pub received: u32,
    pub dropped: u32,
    pub dropped_mac: u32,
    pub dropped_invalid_ether: u32,
    pub dropped_noip: u32,
    pub dropped_filtered: u32,
    pub dropped_invalid_ip: u32,
    pub dropped_bad_cookie: u32,
    pub dropped_invalid_tcp: u32,
    pub dropped_invalid_state: u32,
    pub forwarded: u32,
    pub queued: u32,
    pub overflow: u32,
    pub failed: u32,
}

impl RxStats {
    pub fn empty() -> Self {
        Default::default()
    }

    pub fn clear(&mut self) {
        *self = Default::default();
    }

}

pub struct Ring<'a> {
    cpu: usize,
    netmap: &'a mut NetmapDescriptor,
    stats: RxStats,
    mac: MacAddr,
    ring_num: u16,
    metrics_addr: Option<&'a str>,
}

impl<'a> Ring<'a> {
    pub fn new(ring_num: u16, cpu: usize,
               netmap: &'a mut NetmapDescriptor,
               mac: MacAddr,
               metrics_addr: Option<&'a str>) -> Self {
        Ring {
            ring_num: ring_num,
            cpu: cpu,
            netmap: netmap,
            stats: RxStats::empty(),
            mac: mac,
            metrics_addr: metrics_addr,
        }
    }

    fn update_routing_cache(&mut self) {
        ::RoutingTable::sync_tables();
    }

    fn make_metrics<'t>(tags: &'t [(&'t str, &'t str)]) -> [metrics::Metric<'t>;14] {
        use metrics::Metric;
        [
            Metric::new_with_tags("rx_pps", tags),
            Metric::new_with_tags("rx_drop", tags),
            Metric::new_with_tags("rx_drop_mac", tags),
            Metric::new_with_tags("rx_drop_bad_ether", tags),
            Metric::new_with_tags("rx_drop_noip", tags),
            Metric::new_with_tags("rx_drop_filtered", tags),
            Metric::new_with_tags("rx_drop_bad_ip", tags),
            Metric::new_with_tags("rx_drop_bad_cookie", tags),
            Metric::new_with_tags("rx_drop_bad_tcp", tags),
            Metric::new_with_tags("rx_drop_bad_state", tags),
            Metric::new_with_tags("rx_forwarded", tags),
            Metric::new_with_tags("rx_queued", tags),
            Metric::new_with_tags("rx_overflow", tags),
            Metric::new_with_tags("rx_failed", tags),
        ]
    }

    fn update_metrics<'t>(stats: &'t RxStats, metrics: &mut [metrics::Metric<'a>;14], seconds: u32) {
        metrics[0].set_value((stats.received / seconds) as i64);
        metrics[1].set_value((stats.dropped / seconds) as i64);
        metrics[2].set_value((stats.dropped_mac / seconds) as i64);
        metrics[3].set_value((stats.dropped_invalid_ether / seconds) as i64);
        metrics[4].set_value((stats.dropped_noip / seconds) as i64);
        metrics[5].set_value((stats.dropped_filtered / seconds) as i64);
        metrics[6].set_value((stats.dropped_invalid_ip / seconds) as i64);
        metrics[7].set_value((stats.dropped_bad_cookie / seconds) as i64);
        metrics[8].set_value((stats.dropped_invalid_tcp / seconds) as i64);
        metrics[9].set_value((stats.dropped_invalid_state / seconds) as i64);
        metrics[10].set_value((stats.forwarded / seconds) as i64);
        metrics[11].set_value((stats.queued / seconds) as i64);
        metrics[12].set_value((stats.overflow / seconds) as i64);
        metrics[13].set_value((stats.failed / seconds) as i64);
    }

    fn update_dynamic_metrics(client: &metrics::Client, tags: &[(&str, &str)], seconds: u32) {
        for ip in ::RoutingTable::get_ips() {
            let ip_tag = format!("{}", ip);
            let mut m = metrics::Metric::new_with_tags("rx_pps_ip", tags);
            m.add_tag(("dest_ip", &ip_tag));
            ::RoutingTable::with_host_config_mut(ip, |hc| {
                    m.set_value((hc.packets / seconds) as i64);
                    hc.packets = 0;
            });
            client.send(&[m]);
        }
    }

    // main RX loop
    pub fn run(mut self) {
        let metrics_client = self.metrics_addr.map(metrics::Client::new);
        let hostname = util::get_host_name().unwrap();
        let queue = format!("{}", self.ring_num);
        let ifname = self.netmap.get_ifname();
        let tags = [("queue", queue.as_str()), ("host", hostname.as_str()), ("iface", ifname.as_str())];
        let mut metrics = Self::make_metrics(&tags[..]);

        info!("RX loop for ring {:?}", self.ring_num);
        info!("Rx rings: {:?}", self.netmap.get_rx_rings());
        util::set_thread_name(&format!("syncookied/rx{:02}", self.ring_num));

        util::set_cpu_prio(self.cpu, 20);

        /* wait for card to reinitialize */
        thread::sleep(Duration::new(1, self.ring_num as u32 * 100));
        info!("[RX#{}] started", self.ring_num);

        self.update_routing_cache();

        let mut before = time::Instant::now();
        let seconds: u32 = 5;
        let mut rate: u32 = 0;
        let ival = time::Duration::new(seconds as u64, 0);

        loop {
            if let Some(_) = self.netmap.poll(netmap::Direction::InputOutput) {
                let mut rx_ring = {
                    let mut rx_iter = self.netmap.rx_iter();
                    rx_iter.next().unwrap()
                };
                let mut tx_ring = {
                    let mut tx_iter = self.netmap.tx_iter();
                    tx_iter.next().unwrap()
                };
                if rx_ring.is_empty() {
                    continue;
                }
                if tx_ring.is_empty() {
                    continue;
                }
                self.process_rings(&mut rx_ring, &mut tx_ring);
            }
        }
    }

    fn process_rings(&self, rx_ring: &mut RxRing, tx_ring: &mut TxRing) {
        use std::cmp::min;

        let mut limit = 128;
        limit = min(limit, rx_ring.len());
        limit = min(limit, tx_ring.len());

        for ((rx_slot, rx_buf), (tx_slot, tx_buf)) in rx_ring.iter().zip(tx_ring.iter()).take(limit as usize) {
            match packet::handle_input(rx_buf, self.mac) {
                Action::Drop(reason) => { println!("DROP"); },
                Action::Forward(fwd_mac) => {
                    let tx_idx = tx_slot.get_buf_idx();
                    let tx_len = tx_slot.get_len();

                    tx_slot.set_buf_idx(rx_slot.get_buf_idx());
                    tx_slot.set_len(rx_slot.get_len());
                    tx_slot.set_flags(netmap::NS_BUF_CHANGED);
                
                    rx_slot.set_buf_idx(tx_idx);
                    rx_slot.set_len(tx_len);
                    rx_slot.set_flags(netmap::NS_BUF_CHANGED);

                    {
                        let mut eth = MutableEthernetPacket::new(&mut rx_buf[0..]).unwrap();
                        eth.set_source(self.mac);
                        eth.set_destination(fwd_mac);
                    }
                },
                Action::Reply(packet) => { println!("REPLY"); },
            }
        }
    }
}
