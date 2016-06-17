/// Filtering is implemented with bpf filters
use ::pcap;
use ::pcap::Dead;
use ::bpfjit::BpfJitFilter;

#[derive(Debug,Copy,Clone,PartialEq,Eq)]
pub enum FilterAction {
    Drop,
    Pass
}

pub struct RuleLoader {
    cap: pcap::Capture<Dead>,
}

impl RuleLoader {
    pub fn new() -> Self {
        RuleLoader {
            cap: pcap::Capture::dead(pcap::Linktype(12 /* RAW IP */)).unwrap(),
        }
    }

    // Filters are compiled to bpf bytecode by libcap
    // and then translated to amd64 machine instructions
    // using bpfjit (FreeBSD's BPF JIT compiler)
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

pub fn matches(filters: &[(BpfJitFilter,FilterAction)], buf: &[u8]) -> Option<FilterAction> {
    for &(ref bpf, ref action) in filters {
        if bpf.matched(buf) {
            return Some(*action);
        }
    }
    return None;
}
