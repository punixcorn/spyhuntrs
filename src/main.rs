#![allow(unused_mut)]
#![allow(non_snake_case)]
#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(non_camel_case_types)]
#![allow(unused_assignments)]
#![allow(non_upper_case_globals)]

use colored::Colorize;
use reqwest::dns::Resolve;
use save_util::saveinfo;
use std::error::Error;
use std::path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

mod logging;
// macros in logging
mod save_util;
// save to file
mod banner;
mod cmd_handlers;
mod pathhunt;
mod user_agents;
mod utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    banner::print_banner();
    let agent = user_agents::get_user_agent(true, false).await;
    assert!(agent.len() != 0);
    let target: String = String::from("https://en.wikipedia.org/wiki/Food");
    pathhunt::scan_target(&target).await.unwrap();
    pathhunt::scan_params(&target).await.unwrap();
    Ok(())
}
