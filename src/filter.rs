use ::pcap;
use ::pcap::Dead;
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
            cap: pcap::Capture::dead(pcap::Linktype(1)).unwrap(),
        }
    }
    pub fn parse_rule(&self, rule: &str) -> Result<pcap::BpfProgram,pcap::Error> {
        self.cap.compile(rule)
    }
}
