use ::yaml_rust::{YamlLoader};
use ::yaml_rust::yaml::Yaml;
use std::net::Ipv4Addr;
use std::path::Path;
use std::fs::File;
use std::str::FromStr;
use std::io::Read;
use ::pnet::util::MacAddr;
use ::filter::{RuleLoader,FilterAction};
use ::bpfjit::BpfJitFilter;

// this parser seriously sucks ass, but i'm too tired atm
// and wanna get this shit out asap
// TODO: better error reporting & stuff

//#[derive(Debug)]
#[derive(Clone)]
struct HostConfig {
    ip: Ipv4Addr,
    local_ip: String,
    mac: MacAddr,
    filters: Vec<(BpfJitFilter,FilterAction)>,
    default_policy: FilterAction,
}

// some crazy shit
pub fn configure(path: &Path) -> Vec<(Ipv4Addr, String)> {
    let hosts = ConfigLoader::new(path).load();
    let mut ips = vec![];
    ::RoutingTable::clear();
    for host in hosts {
        ::RoutingTable::add_host(host.ip, host.mac, host.default_policy, host.filters);
        //::RoutingTable::with_host_config(host.ip, |hc| println!("{:?}", hc));
        ips.push((host.ip, host.local_ip));
    }
    ips
}

struct ConfigLoader {
    rule_loader: RuleLoader,
    root: Vec<Yaml>,
}

impl ConfigLoader {
    pub fn new(path: &Path) -> Self {
        ConfigLoader {
            rule_loader: RuleLoader::new(),
            root: Self::parse_file(path),
        }
    }

    fn parse_file(path: &Path) -> Vec<Yaml> {
        let mut f = File::open(path).expect("Expected hosts.yml in current directory");
        let mut s = String::new();

        f.read_to_string(&mut s).unwrap();
        YamlLoader::load_from_str(&s).unwrap()
    }

    pub fn load(&self) -> Vec<HostConfig> {
        let mut res = vec![];
        for doc in self.root.iter() {
            res.extend_from_slice(&self.parse_doc(doc));
        }
        res
    }

    fn parse_doc(&self, doc: &Yaml) -> Vec<HostConfig> {
        let hosts = vec![];
        match *doc {
            Yaml::Array(ref arr) => {
                return arr.iter().filter_map(|x| self.parse_host(x)).collect();
            },
            _ => {
                println!("Top level must be an array of hashes");
                return hosts;
            }
        }
    }

    fn parse_filters(&self, doc: &Yaml) -> (FilterAction, Vec<(BpfJitFilter,FilterAction)>) {
        let mut res = vec![];
        let mut default_policy = FilterAction::Pass;

        match *doc {
            Yaml::Hash(ref h) => {
                for (k, v) in h {
                    match (k, v) {
                        (&Yaml::String(ref key), &Yaml::String(ref val)) => {
                            let action = match val as &str {
                                "drop" => FilterAction::Drop,
                                "pass" => FilterAction::Pass,
                                _ => {
                                    println!("filter action should be one of 'drop' or 'pass'");
                                    return (default_policy, res);
                                }
                            };
                            if key == "default" {
                                default_policy = action;
                            }
                            if let Ok(bpf) = self.rule_loader.parse_rule(key) {
                                res.push((bpf, action));
                            }
                        },
                        _ => println!("bad syntax in filter"),
                    }
                }
            },
            _ => {
                println!("Bad filters syntax");
            }
        }
        (default_policy, res)
    }

    fn parse_host(&self, doc: &Yaml) -> Option<HostConfig> {
        let mut ip = None;
        let mut local_ip = None;
        let mut mac = None;
        let mut filters = vec![];
        let mut default_policy = FilterAction::Pass;

        match *doc {
            Yaml::Hash(ref h) => {
                for (k, v) in h {
                    match (k, v) {
                        (&Yaml::String(ref key), &Yaml::String(ref val)) => {
                            if key == "ip" {
                                ip = Ipv4Addr::from_str(val).ok();
                            } else if key == "local_ip" {
                                local_ip = Some(val.clone());
                            } else if key == "mac" {
                                mac = MacAddr::from_str(val).ok();
                            } else {
                                println!("unknown key: {}", key);
                            }
                        },
                        (&Yaml::String(ref key), _) => {
                            if key == "filters" {
                                let tuple = self.parse_filters(v);
                                default_policy = tuple.0;
                                filters = tuple.1;
                            }
                        },
                        _ => {
                            println!("Invalid key {:?} or val {:?}", k, v);
                            return None;
                        },
                    }
                }
            },
            _ => {
                println!("Invalid doc type");
                return None;
            }
        }
        if ip.is_some() && local_ip.is_some() && mac.is_some() {
            return Some(HostConfig {
                ip: ip.unwrap(),
                local_ip: local_ip.unwrap(),
                mac: mac.unwrap(),
                filters: filters,
                default_policy: default_policy,
            });
        }
        None
    }
}

#[test]
fn fuck() {
    parse_file(Path::new("hosts.yml"));
    ConfigLoader::new(Path::new("hosts.yml")).parse_all();
}
