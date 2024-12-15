#![allow(unused_mut)]
#![allow(non_snake_case)]
#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(non_camel_case_types)]
#![allow(unused_assignments)]
#![allow(non_upper_case_globals)]
#![allow(unused_macros)]
#![allow(unreachable_code)]

use cmd_handlers::cmd_info;
use colored::Colorize;
use dns_lookup::lookup_addr;
use reqwest::dns::Resolve;
use reqwest::{header, ClientBuilder, Response};
use save_util::{check_if_save, get_save_file, save_string, save_vec_strs, set_save_file};
use shodan_client::*;
use soup::pattern::Pattern;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::path::{self, Path};
use std::str::{FromStr, SplitTerminator};
use std::string;
use std::sync::{Arc, Mutex};
use utils::file_exists;

/// handles the save option state
pub static save: Mutex<bool> = Mutex::new(true);
pub static save_file: Mutex<String> = Mutex::new(String::new());

mod logging;
// macros in logging
mod save_util;
// save to file
mod request;
// make requests
mod banner;
mod cmd_handlers;
mod pathhunt;
mod user_agents;
mod utils;
mod waybackmachine;

/// get the ip for a domain
/// done
fn get_revese_ip(domain: Vec<&str>) -> Option<String> {
    for d in domain {
        let ips: Option<Vec<_>> = match dns_lookup::lookup_host(d) {
            Ok(ips) => Some(ips),
            _ => None,
        };
        match ips {
            Some(ip) => {
                match ip.get(0) {
                    Some(v4) => {
                        let ip_v4 = v4.to_string();
                        info!(format!("{d} : [{ip_v4}]"));
                        handle_data!(ip_v4, String);
                    }
                    _ => warn!(format!("could not parse data gotten from lookup for {}", d)),
                };
            }
            _ => warn!(format!("no ip gotten for {}", d)),
        };
    }
    None
}

async fn shodan_api(api_key: String, query: String, extract_domain_only: bool) {
    let client = ShodanClient::new(api_key);
    let x = client.host_search(query, None, None, None).await.unwrap();
    let y = x.matches;

    if extract_domain_only {
        // get domains
        for i in &y {
            for domain in &i.domains {
                info!(format!("ss"));
                handle_data!(domain.to_string(), String);
            }
        }
    } else {
        // get everything
        for i in &y {
            let entry = format!(
                "{} | {} | {} | {} | {} | {} | {} | {} | {}",
                i.hash,
                i.asn.clone().unwrap_or("None".to_string()),
                i.os.clone().unwrap_or("None".to_string()),
                i.timestamp,
                i.transport,
                i.ip_str,
                i.product.clone().unwrap_or("None".to_string()),
                i.port,
                i.ipv6.clone().unwrap_or("None".to_string())
            );

            info!(entry);
            handle_data!(entry, String);
        }
    }
}

pub async fn subdomain_finder(domain: Vec<&str>) {
    let certsh_path = " ./scripts/certsh.sh".to_string();
    let spotter_path = "./scripts/spotter.sh".to_string();

    if !file_exists(&certsh_path) || !file_exists(&spotter_path) {
        err!(format!(
            "{} or {} does not exist",
            certsh_path, spotter_path
        ));
    };

    // run subfinder -d {domain} -silent
    for d in &domain {
        match cmd_handlers::run_cmd_string(format!("subfinder -d {} -silent", d)) {
            Some(data) => {
                match data.stdout {
                    Some(x) => {
                        for i in x.split('\n').into_iter() {
                            info!(format!("{}\n", i));
                            handle_data!(i, &str);
                        }
                    }
                    None => todo!(),
                };
            }
            None => !todo!(),
        }
    }

    // closure to run scripts
    let run_scripts = |str1: String| {
        for d in &domain {
            match cmd_handlers::run_piped_strings(str1.clone(), "uniq".to_string()) {
                Some(data) => {
                    match data.stdout {
                        Some(x) => {
                            for i in x.split('\n').into_iter() {
                                info!(format!("{}\n", i));
                                handle_data!(i, &str);
                            }
                        }
                        None => todo!(),
                    };
                }
                None => !todo!(),
            }
        }
    };

    // run spotter
    run_scripts(spotter_path);
    // run certsh
    run_scripts(certsh_path);
}

/// perform a webcrawl using hakrawler
/// done
pub fn webcrawler(domain: Vec<&str>) {
    for d in domain {
        let cmd = cmd_handlers::run_piped_strings(
            format!("echo {}", d),
            format!("hakrawler >> {}", get_save_file()),
        );
    }
}

pub fn status_code(domain: &str) {
    let xmd = cmd_handlers::run_piped_strings(
        format!("echo {}", domain),
        "httpx -silent -status-code".to_string(),
    );
}

pub async fn enumerate_domain(domain: &str) -> Option<String> {
    let mut servers: Vec<_> = vec![];
    let resp = fetch_url_unwrap!(domain.to_string());
    if resp.status().is_success()
        || resp.status().is_redirection()
        || resp.status().is_informational()
    {
        let d = domain.trim().replace("https://", "").replace("http://", "");
        let headers = resp.headers();
        for (key, value) in headers.iter() {
            if key == "Server" || key == "server" {
                servers.push(value);
            }
        }

        println!("{:?}", servers);
        return Some(d.to_string());
    }

    return None;
}

pub async fn get_favicon(target: String) -> Option<String> {
    let new_url = request::urljoin(target.clone(), "/favicon.ico".to_string());
    let resp = fetch_url!(new_url.clone());
    println!("{:#?}", resp);
    match resp {
        Ok(body) => {
            if body.status().is_success() {
                return Some(new_url);
            }
            return None;
        }
        _ => {
            warn!(format!("could not find favicon for {}", target.clone()));
            return None;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    banner::print_simple_banner();
    let target: String = "en.wikipedia.org".to_string();

    // let agent = user_agents::get_user_agent(true, false).await;
    // assert!(agent.len() != 0);
    // pathhunt::scan_target(&target).await.unwrap();
    // pathhunt::scan_params(&target).await.unwrap();
    // waybackmachine::get_wayback_snapshot(target).await;
    // waybackmachine::waybackmachine_scan(target).await.unwrap();
    // get_revese_ip(target.as_str()).unwrap();
    // set_save_option(true);
    // webcrawler(target.as_str());
    // status_code(target.as_str());
    // get_favicon(target).await;
    // enumerate_domain(target.as_str()).await.unwrap();

    if check_if_save() {
        set_save_file("newfile.txt");
    }
    let api_key: String = "XBB0IcjOcI5dAZ1ZwAXSr4U5ChL8HAk8".to_string();
    shodan_api(api_key, "spankki.fi".to_string(), false).await;

    Ok(())
}
