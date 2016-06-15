use ::pcap;
use ::pcap::Dead;
use ::pcap::BpfProgram;
use std::path::Path;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;

pub struct RuleLoader {
    cap: pcap::Capture<Dead>,
}

impl RuleLoader {
    pub fn new() -> Self {
        RuleLoader {
            cap: pcap::Capture::dead(pcap::Linktype(12 /* RAW IP */)).unwrap(),
        }
    }
    pub fn parse_rule(&self, rule: &str) -> Result<pcap::BpfProgram,pcap::Error> {
        self.cap.compile(rule)
    }
}

pub fn matches(filters: &[BpfProgram], buf: &[u8]) -> bool {
    filters.iter().all(|bpf| bpf.filter(buf))
}
