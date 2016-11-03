/// Ring thread
use std::time::{self,Duration};
use std::thread;
use ::netmap::{self, NetmapDescriptor, NetmapSlot, NetmapRing, RxRing, TxRing};
use ::pnet::packet::ethernet::MutableEthernetPacket;
use ::packet;
use ::pnet::util::MacAddr;
use ::util;
use ::packet::{Action,Reason};
use ::metrics;

#[derive(Debug,Default)]
struct RingStats {
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
    pub syn_received: u32,
    pub sent: u32,
    pub failed: u32,
}

impl RingStats {
    pub fn empty() -> Self {
        Default::default()
    }

    pub fn clear(&mut self) {
        *self = Default::default();
    }

}

pub struct Worker<'a> {
    cpu: usize,
    netmap: &'a mut NetmapDescriptor,
    mac: MacAddr,
    ring_num: u16,
    metrics_addr: Option<&'a str>,
}

impl<'a> Worker<'a> {
    pub fn new(ring_num: u16, cpu: usize,
               netmap: &'a mut NetmapDescriptor,
               mac: MacAddr,
               metrics_addr: Option<&'a str>) -> Self {
        Worker {
            ring_num: ring_num,
            cpu: cpu,
            netmap: netmap,
            mac: mac,
            metrics_addr: metrics_addr,
        }
    }

    fn update_routing_cache(&self) {
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
            Metric::new_with_tags("rx_syn", tags),
            Metric::new_with_tags("tx_pps", tags),
            Metric::new_with_tags("tx_failed", tags),
        ]
    }

    fn update_metrics<'t>(stats: &'t RingStats, metrics: &mut [metrics::Metric<'a>;14], seconds: u32) {
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
        metrics[11].set_value((stats.syn_received / seconds) as i64);
        metrics[12].set_value((stats.sent / seconds) as i64);
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
    #[inline(never)]
    pub fn run(mut self) {
        let metrics_client = self.metrics_addr.map(metrics::Client::new);
        let hostname = util::get_host_name().unwrap();
        let queue = format!("{}", self.ring_num);
        let ifname = self.netmap.get_ifname();
        let tags = [("queue", queue.as_str()), ("host", hostname.as_str()), ("iface", ifname.as_str())];
        let mut metrics = Self::make_metrics(&tags[..]);
        let mut stats = RingStats::empty();

        info!("RX/TX loop for ring {:?}", self.ring_num);
        info!("Rx rings: {:?}", self.netmap.get_rx_rings());
        info!("Tx rings: {:?}", self.netmap.get_tx_rings());
        util::set_thread_name(&format!("syncookied/{:02}", self.ring_num));

        util::set_cpu_prio(self.cpu, 20);

        /* wait for card to reinitialize */
        thread::sleep(Duration::new(1, self.ring_num as u32 * 100));
        info!("[RX/TX#{}] started", self.ring_num);

        self.update_routing_cache();

        let mut before = time::Instant::now();
        let seconds: u32 = 5;
        let mut rate: u32 = 0;
        let ival = time::Duration::new(seconds as u64, 0);

        let mut flags = netmap::Direction::InputOutput;
        loop {
            if let Some(_) = self.netmap.poll(flags) {
                let mut rx_ring = {
                    let mut rx_iter = self.netmap.rx_iter();
                    rx_iter.next().unwrap()
                };
                let mut tx_ring = {
                    let mut tx_iter = self.netmap.tx_iter();
                    tx_iter.next().unwrap()
                };
                let rx_empty = rx_ring.is_empty();
                let tx_empty = tx_ring.is_empty();

                if rx_empty && tx_empty {
                    flags = netmap::Direction::InputOutput;
                    continue;
                }
                if rx_empty {
                    flags = netmap::Direction::Input;
                    continue;
                }
                if tx_empty {
                    flags = netmap::Direction::Output;
                    continue;
                }
                if rate < 100 {
                    self.update_routing_cache();
                }
                self.process_rings(&mut rx_ring, &mut tx_ring, &mut stats);
            }
            if before.elapsed() >= ival {
                if let Some(ref metrics_client) = metrics_client {
                    Self::update_metrics(&stats, &mut metrics, seconds);
                    metrics_client.send(&metrics);
                    Self::update_dynamic_metrics(metrics_client, &tags, seconds);
                }
                rate = stats.received/seconds;
                debug!("[RX/TX#{}]: received: {}Pkts/s, dropped: {}Pkts/s, forwarded: {}Pkts/s, syn_received: {}Pkts/s, failed: {}Pkts/s",
                            self.ring_num, rate, stats.dropped/seconds,
                            stats.forwarded/seconds, stats.syn_received/seconds,
                            stats.failed/seconds);
                stats.clear();
                before = time::Instant::now();
                self.update_routing_cache();
            }
        }
    }

    fn process_rings(&self, rx_ring: &mut RxRing, tx_ring: &mut TxRing, stats: &mut RingStats) {
        use std::cmp::min;

        let mut limit = 1024;
        limit = min(limit, rx_ring.len());
        limit = min(limit, tx_ring.len());

        let mut i = 0;

        for ((rx_slot, rx_buf), (tx_slot, tx_buf)) in rx_ring.iter().zip(tx_ring.iter()).take(limit as usize) {
            i += 1;
            stats.received += 1;
            match packet::handle_input(rx_buf, self.mac) {
                Action::Drop(reason) => {
                     stats.dropped += 1;
                     match reason {
                         Reason::MacNotFound => stats.dropped_mac += 1,
                         Reason::InvalidEthernet => stats.dropped_invalid_ether += 1,
                         Reason::IpNotFound => stats.dropped_invalid_ip += 1,
                         Reason::Filtered => stats.dropped_filtered += 1,
                         Reason::InvalidIp => stats.dropped_invalid_ip += 1,
                         Reason::BadCookie => stats.dropped_bad_cookie += 1,
                         Reason::InvalidTcp => stats.dropped_invalid_tcp += 1,
                         Reason::StateNotFound => stats.dropped_invalid_state += 1,
                     }
                },
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
                    stats.forwarded += 1;
                    stats.sent += 1;
                },
                Action::Reply(ref packet) => {
                    stats.syn_received += 1;
                    if let Some(len) = packet::handle_reply(packet, self.mac, tx_buf) {
                        tx_slot.set_flags(0);
                        tx_slot.set_len(len as u16);
                        stats.sent += 1;
                    } else {
                        stats.failed += 1;
                    }
                },
            }
        }
    }
}
