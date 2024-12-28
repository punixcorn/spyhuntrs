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

use {
    colored::Colorize,
    rayon::prelude::*,
    reqwest::{dns::Resolve, header, ClientBuilder, Response},
    save_util::{check_if_save, get_save_file, save_string, save_vec_strs, set_save_file},
    serde_json::to_string,
    std::{
        env::{args, Args},
        error::Error,
        sync::{Arc, Mutex},
    },
};

/// handles the save option state
pub static save: Mutex<bool> = Mutex::new(true);
pub static save_file: Mutex<String> = Mutex::new(String::new());

mod logging;
mod tests;
// comment for auto formatter to put macros in logging above the others
mod save_util;
// save to file
mod banner;
mod cmd_handlers;
mod favicon;
mod file_util;
mod google_search;
mod pathhunt;
mod request;
mod spyhunt_util;
mod user_agents;
mod waybackmachine;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    banner::print_simple_banner();
    let target: String = "en.wikipedia.com".to_string();
    let domain: String = target.clone();
    let domains = ["google.com", "food.com", "en.wikipedia.com"];
    if check_if_save() {
        set_save_file("newfile.txt");
    }
    /*
        let agent = user_agents::get_user_agent(true, false).await;
        assert!(agent.len() != 0);
        pathhunt::scan_target(&target).await.unwrap();
        pathhunt::scan_params(&target).await.unwrap();
        waybackmachine::get_wayback_snapshot(target.clone()).await;
        waybackmachine::waybackmachine_scan(target.clone())
            .await
            .unwrap();
        save_util::set_save_option(true);
        spyhunt_util::webcrawler(domains.to_vec());
        spyhunt_util::status_code(target.clone().as_str());

        spyhunt_util::enumerate_domain(target.as_str())
            .await
            .unwrap();

        let api_key: String = "XBB0IcjOcI5dAZ1ZwAXSr4U5ChL8HAk8".to_string();
        spyhunt_util::shodan_api(api_key, "spankki.fi".to_string(), false).await;
        spyhunt_util::status_code_reqwest(target.as_str()).await;
        spyhunt_util::status_code(target.as_str());
        spyhunt_util::run_cors_misconfig_threads([target.as_str()].to_vec()).await;
        spyhunt_util::run_cors_misconfig_threads(domains.to_vec()).await;
        let x = favicon::init();
        println!("{:#?}", x);
        match spyhunt_util::get_favicon_hash("https://www.skype.com/en/".to_string()).await {
            Some(k) => println!("{:#?}", k),
            None => (),
        };
        spyhunt_util::probe(domain.clone());
        spyhunt_util::network_analyzer(target.clone());
        spyhunt_util::redirects(target.clone());
        spyhunt_util::brokenlinks(target.clone());
        spyhunt_util::tech::find_tech("en.wikipedia.com".to_string()).await;
        spyhunt_util::paramspider(domain.clone());
        spyhunt_util::get_reverse_ip(["8.8.8.8"].to_vec());
        spyhunt_util::google(domain.clone()).await;
        match google_search::v2::user_agent::search("en.wikipedia.com".to_string(), 10).await {
            Ok(data) => data.into_iter().for_each(|x| {
                println!("{:#?}", x);
            }),
            Err(_) => {}
        };

        println!("no user agent:");
        match google_search::v2::no_user_agent::search("en.wikipedia.com".to_string(), 10).await {
            Ok(data) => data.into_iter().for_each(|x| {
                println!("{:#?}", x);
            }),
            Err(_) => {}
        };
        spyhunt_util::cidr_notation::cidr_notation("127.0.0.1");
        spyhunt_util::print_all_ips("127.0.0.1").unwrap();
    */

    Ok(())
}
