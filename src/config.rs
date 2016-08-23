/// Configuration file parser and related functions

use ::yaml_rust::{self,YamlLoader};
use ::yaml_rust::yaml::Yaml;
use std::net::{Ipv4Addr,SocketAddr,AddrParseError};
use std::path::Path;
use std::fs::File;
use std::str::FromStr;
use std::io::{self,Read};
use ::pnet::util::MacAddr;
use ::filter::{RuleLoader,FilterAction};
use ::bpfjit::BpfJitFilter;

//#[derive(Debug)]
#[derive(Clone)]
pub struct HostConfig {
    pub ip: Ipv4Addr,
    pub local_ip: SocketAddr,
    pub mac: MacAddr,
    pub filters: Vec<(BpfJitFilter,FilterAction)>,
    pub default_policy: FilterAction,
    pub passthrough: bool,
}

// this is called on startup and reload
pub fn configure(path: &Path) -> Result<Vec<(Ipv4Addr, SocketAddr)>, ConfigLoadingError> {
    let loader = try!(ConfigLoader::new(path));
    let hosts = try!(loader.load());
    let mut ips = vec![];
    ::RoutingTable::clear();
    for host in hosts {
        ::RoutingTable::add_host(&host);
        //::RoutingTable::with_host_config(host.ip, |hc| println!("{:?}", hc));
        ips.push((host.ip, host.local_ip));
    }
    Ok(ips)
}

struct ConfigLoader {
    rule_loader: RuleLoader,
    root: Vec<Yaml>,
}

#[derive(Debug)]
pub enum ConfigLoadingError {
    FileError(io::Error),
    Yaml(yaml_rust::ScanError),
    Semantic(String),
}

impl ConfigLoadingError {
    fn semantic(s: String) -> Self {
        ConfigLoadingError::Semantic(s)
    }
}

impl From<io::Error> for ConfigLoadingError {
    fn from(e: io::Error) -> Self {
        ConfigLoadingError::FileError(e)
    }
}

impl From<yaml_rust::ScanError> for ConfigLoadingError {
    fn from(e: yaml_rust::ScanError) -> Self {
        ConfigLoadingError::Yaml(e)
    }
}

impl From<AddrParseError> for ConfigLoadingError {
    fn from(e: AddrParseError) -> Self {
        ConfigLoadingError::semantic(e.to_string())
    }
}

// atm parser tries to ignore errors as much as possible
// TODO: better error reporting & stuff
impl ConfigLoader {
    pub fn new(path: &Path) -> Result<Self, ConfigLoadingError> {
        let yaml = try!(Self::parse_file(path));
        Ok(ConfigLoader {
            rule_loader: RuleLoader::new(),
            root: yaml,
        })
    }

    fn parse_file(path: &Path) -> Result<Vec<Yaml>, ConfigLoadingError> {
        let mut f = try!(File::open(path));
        let mut s = String::new();

        try!(f.read_to_string(&mut s));
        YamlLoader::load_from_str(&s).map_err(|e| e.into())
    }

    pub fn load(&self) -> Result<Vec<HostConfig>, ConfigLoadingError> {
        let mut res = vec![];
        for doc in self.root.iter() {
            let doc = try!(self.parse_doc(doc));
            res.extend_from_slice(&doc);
        }
        Ok(res)
    }

    fn parse_doc(&self, doc: &Yaml) -> Result<Vec<HostConfig>, ConfigLoadingError> {
        match *doc {
            Yaml::Array(ref arr) => {
                let mut result = vec![];
                for item in arr {
                    let item = try!(self.parse_host(item));
                    result.push(item);
                }
                Ok(result)
            },
            _ => {
                Err(ConfigLoadingError::semantic("Top level must be an array of hashes".to_owned()))
            }
        }
    }

    fn parse_filters(&self, doc: &Yaml) -> Result<(FilterAction, Vec<(BpfJitFilter,FilterAction)>), ConfigLoadingError> {
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
                                    return Err(ConfigLoadingError::semantic(
                                            "filter action should be one of 'drop' or 'pass'".to_owned()
                                            ));
                                }
                            };
                            if key == "default" {
                                default_policy = action;
                                continue;
                            }
                            match self.rule_loader.parse_rule(key) {
                                Ok(bpf) => res.push((bpf, action)),
                                Err(e) => return Err(ConfigLoadingError::semantic(
                                    e.to_string()
                                )),
                            };
                        },
                        _ => return Err(ConfigLoadingError::semantic("bad syntax in filter".to_string())),
                    }
                }
            },
            _ => {
                return Err(ConfigLoadingError::semantic("bad filter syntax".to_string()));
            }
        }
        Ok((default_policy, res))
    }

    fn validate_mac(mac: &str) -> Result<MacAddr,ConfigLoadingError> {
        match MacAddr::from_str(mac) {
            Err(e) => Err(ConfigLoadingError::semantic(format!("{:?}", e))),
            Ok(mac) => Ok(mac),
        }
    }

    fn parse_host(&self, doc: &Yaml) -> Result<HostConfig,ConfigLoadingError> {
        let mut ip = None;
        let mut local_ip = None;
        let mut mac = None;
        let mut pt = false;
        let mut filters = vec![];
        let mut default_policy = FilterAction::Pass;

        match *doc {
            Yaml::Hash(ref h) => {
                for (k, v) in h {
                    match (k, v) {
                        (&Yaml::String(ref key), &Yaml::String(ref val)) => {
                            if key == "ip" {
                                ip = Some(try!(Ipv4Addr::from_str(val)));
                            } else if key == "local_ip" || key == "secrets_addr" {
                                local_ip = Some(try!(SocketAddr::from_str(val)));
                            } else if key == "mac" {
                                mac = Some(try!(Self::validate_mac(val)));
                            } else {
                                return Err(ConfigLoadingError::semantic(format!("unknown key: {}", key)));
                            }
                        },
                        (&Yaml::String(ref key), &Yaml::Boolean(val)) => {
                            if key == "passthrough" {
                                pt = val;
                            } else {
                                return Err(ConfigLoadingError::semantic(format!("unknown key: {}", key)));
                            }
                        }, 
                        (&Yaml::String(ref key), _) => {
                            if key == "filters" {
                                let tuple = try!(self.parse_filters(v));
                                default_policy = tuple.0;
                                filters = tuple.1;
                            }
                        },
                        _ => {
                            return Err(ConfigLoadingError::semantic(format!("Invalid key {:?} or val {:?}", k, v)));
                        },
                    }
                }
            },
            _ => {
                return Err(ConfigLoadingError::semantic("Invalid doc type".into()));
            }
        }
        Ok(HostConfig {
            ip: ip.unwrap(),
            local_ip: local_ip.unwrap(),
            mac: mac.unwrap(),
            filters: filters,
            default_policy: default_policy,
            passthrough: pt,
        })
    }
}
