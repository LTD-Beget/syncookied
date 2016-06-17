use ::pcap;
use ::pcap::Dead;
use ::pcap::BpfProgram;
use ::bpfjit::BpfJitFilter;
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
    pub fn parse_rule(&self, rule: &str) -> Result<BpfJitFilter,pcap::Error> {
        use std::mem;
        match self.cap.compile(rule) {
            Ok(prog) => {
                let insns = unsafe { mem::transmute(prog.get_instructions()) };
                Ok(BpfJitFilter::compile(insns).unwrap())
            },
            Err(e) => Err(e),
        }
    }
}

pub fn matches(filters: &[BpfJitFilter], buf: &[u8]) -> bool {
    filters.iter().all(|bpf| bpf.matched(buf))
}
