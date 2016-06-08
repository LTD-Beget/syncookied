use ::yaml_rust::{YamlLoader};
use ::yaml_rust::yaml::Yaml;
use std::net::Ipv4Addr;
use std::path::Path;
use std::fs::File;
use std::str::FromStr;
use std::io::Read;
use ::pnet::util::MacAddr;

// this parser seriously sucks ass, but i'm too tired atm
// and wanna get this shit out asap
// TODO: better error reporting & stuff

#[derive(Debug)]
struct HostConfig {
    ip: Ipv4Addr,
    local_ip: String,
    mac: MacAddr,
}

fn parse_host(doc: &Yaml) -> Option<HostConfig> {
    let mut ip = None;
    let mut local_ip = None;
    let mut mac = None;

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
        return Some(HostConfig { ip: ip.unwrap(), local_ip: local_ip.unwrap(), mac: mac.unwrap() });
    }
    None
}

fn parse_config(doc: &Yaml) -> Vec<HostConfig> {
    let hosts = vec![];
    match *doc {
        Yaml::Array(ref arr) => {
            return arr.iter().filter_map(parse_host).collect();
        },
        _ => {
            println!("Top level must be an array of hashes");
            return hosts;
        }
    }
}

fn parse_file(path: &Path) -> Vec<HostConfig> {
    let mut f = File::open(path).unwrap();
    let mut s = String::new();
    let mut hosts = vec![];

    f.read_to_string(&mut s).unwrap();
    let docs = YamlLoader::load_from_str(&s).unwrap();
    for doc in docs {
        hosts.append(&mut parse_config(&doc));
    }
    hosts
}

// some crazy shit
pub fn configure() -> Vec<(Ipv4Addr, String)> {
    let hosts = parse_file(Path::new("hosts.yml"));
    let mut ips = vec![];
    for host in hosts {
        ::RoutingTable::add_host(host.ip, host.mac);
        ::RoutingTable::with_host_config(host.ip, |hc| println!("{:?}", hc));
        ips.push((host.ip, host.local_ip));
    }
    ips
}

#[test]
fn fuck() {
    println!("{:?}", parse_file(Path::new("hosts.yml")));
}
