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

use colored::Colorize;
use reqwest::{dns::Resolve, header, ClientBuilder, Response};
use save_util::{check_if_save, get_save_file, save_string, save_vec_strs, set_save_file};
use spyhunt_util::{status_code, status_code_reqwest};
use std::{
    error::Error,
    sync::{Arc, Mutex},
};

/// handles the save option state
pub static save: Mutex<bool> = Mutex::new(true);
pub static save_file: Mutex<String> = Mutex::new(String::new());

mod logging;
// should macros in logging

mod save_util;
// save to file
mod banner;
mod cmd_handlers;
mod file_util;
mod pathhunt;
mod request;
mod spyhunt_util;
mod user_agents;
mod waybackmachine;

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

    // let api_key: String = "XBB0IcjOcI5dAZ1ZwAXSr4U5ChL8HAk8".to_string();
    // util::shodan_api(api_key, "spankki.fi".to_string(), false).await;

    status_code_reqwest(target.as_str()).await;
    status_code(target.as_str());

    Ok(())
}
