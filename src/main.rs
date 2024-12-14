#![allow(unused_mut)]
#![allow(non_snake_case)]
#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(non_camel_case_types)]
#![allow(unused_assignments)]
#![allow(non_upper_case_globals)]

use cmd_handlers::{cmd_info, run_cmd, run_piped};
use colored::Colorize;
use dns_lookup::lookup_addr;
use reqwest::dns::Resolve;
use reqwest::Response;
use save_util::saveinfo;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

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

fn get_revese_ip(domain: &str) -> Option<String> {
    let ips: Option<Vec<_>> = match dns_lookup::lookup_host(domain) {
        Ok(ips) => Some(ips),
        _ => None,
    };

    match ips {
        Some(ip) => Some(ip.get(0)?.to_string()),
        _ => None,
    }
}

/// handles the save option state
pub static save: Mutex<bool> = Mutex::new(false);

/// checks if the save option was set in args
pub fn check_if_save() -> bool {
    let x = save.lock().unwrap();
    return x.clone();
}

/// sets the save option state vaule
pub fn set_save_option(value: bool) {
    let mut x = save.lock().unwrap();
    *x = value;
}

pub fn webcrawler(domain: &str) {
    let xmd = run_piped(["echo", domain].to_vec(), ["hakrawler"].to_vec()).unwrap();
}

pub fn status_code(domain: &str) {
    let xmd = run_piped(
        ["echo", domain].to_vec(),
        ["httpx", "-silent", "-status-code"].to_vec(),
    )
    .unwrap();
}

pub async fn enumerate_domain(domain: &str) -> Option<String> {
    let mut servers: Vec<&str> = vec![];
    let x = request::fetch(domain.to_string(), "".to_string())
        .await
        .unwrap();
    if x.status().is_success() || x.status().is_redirection() || x.status().is_informational() {
        let x = domain.trim().replace("https://", "").replace("http://", "");
        return Some(x.to_string());
    }

    return None;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    banner::print_banner();
    let target: String = "en.wikipedia.org".to_string();

    // let agent = user_agents::get_user_agent(true, false).await;
    // assert!(agent.len() != 0);
    // pathhunt::scan_target(&target).await.unwrap();
    // pathhunt::scan_params(&target).await.unwrap();
    // waybackmachine::get_wayback_snapshot(target).await;
    // waybackmachine::waybackmachine_scan(target).await.unwrap();
    // get_revese_ip(target.as_str()).unwrap();
    // set_save_option(true);
    // if check_if_save() {
    //     println!("save was set");
    // } else {
    //     println!("save was not set");
    // }
    //webcrawler();
    status_code(target.as_str());
    Ok(())
}
