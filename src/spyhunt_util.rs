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

use crate::{
    cmd_handlers,
    cmd_handlers::cmd_info,
    file_util::file_exists,
    request, save_util,
    save_util::{check_if_save, get_save_file, save_string, save_vec_strs, set_save_file},
};

// above all
use colored::Colorize;
use dns_lookup::lookup_addr;
use reqwest::{dns::Resolve, header, ClientBuilder, Response};
use shodan_client::*;
use soup::pattern::Pattern;

use std::{
    error::Error,
    net::{IpAddr, SocketAddr},
    path::{self, Path, PathBuf},
    str::{FromStr, SplitTerminator},
    string,
    sync::{Arc, Mutex},
};

/// get the ip for a domain [Completed]
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

/// find subdomains using shodan [completed]
/// if extract_sub_domain_only is triggered, the output will be a list of subdomains only
pub async fn shodan_api(api_key: String, domain: String, extract_domain_only: bool) {
    let client = ShodanClient::new(api_key);
    let x = client.host_search(domain, None, None, None).await.unwrap();
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
                "{} | {} | {} | {} | {} | {} | {} | {} | {} | [{}]",
                i.hash,
                i.asn.clone().unwrap_or("None".to_string()),
                i.os.clone().unwrap_or("None".to_string()),
                i.timestamp,
                i.transport,
                i.ip_str,
                i.product.clone().unwrap_or("None".to_string()),
                i.port,
                i.ipv6.clone().unwrap_or("None".to_string()),
                i.domains.join(",")
            );

            info!(entry);
            handle_data!(entry, String);
        }
    }
}

/// find subdomains in a domain [completed]
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
                    None => warn!(format!("{d} : error occured")),
                };
            }
            None => warn!(format!("{d} : error occured")),
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
                        None => warn!(format!("{d} : error occured")),
                    };
                }
                None => warn!(format!("{d} : error occured")),
            }
        }
    };

    // run spotter
    run_scripts(spotter_path);
    // run certsh
    run_scripts(certsh_path);
}

/// perform a webcrawl using hakrawler [completed]
pub fn webcrawler(domain: Vec<&str>) {
    for d in domain {
        let cmd = cmd_handlers::run_piped_strings(
            format!("echo {}", d),
            format!("hakrawler >> {}", get_save_file()),
        );
    }
}

/// get status code of domain using httpx [completed]
pub fn status_code(domain: &str) {
    let xmd = cmd_handlers::run_piped_strings(
        format!("echo {}", domain),
        "httpx -silent -status-code".to_string(),
    );
    match xmd {
        Some(srt) => {
            let x = format!(
                "{domain} [{}]",
                srt.stdout.unwrap_or_else(|| { "err".to_string() })
            );
            info!(x);
            handle_data!(x, String);
        }
        _ => warn!(format!("err occured for {domain}")),
    }
}

/// get status code of domain using reqwest [completed]
pub async fn status_code_reqwest(domain: &str) {
    let d = domain.trim().replace("https://", "").replace("http://", "");
    let mut code: u16 = 0;
    let resp = fetch_url!(domain.to_string());
    match resp {
        Ok(data) => {
            info!(format!("{d} [{}]", data.status().as_u16()));
            handle_data!(format!("{d} [{}]", data.status().as_u16()), String);
        }
        Err(_) => warn!(format!("{d} [no infomation]")),
    };
}

/// enumate domain for server info and ip [completed]
pub async fn enumerate_domain(domain: &str) -> Option<String> {
    let mut server: &str = "unknown";
    let resp = fetch_url_unwrap!(domain.to_string());
    if resp.status().is_success()
        || resp.status().is_redirection()
        || resp.status().is_informational()
    {
        let d = domain.trim().replace("https://", "").replace("http://", "");
        let headers = resp.headers();
        for (key, value) in headers.iter() {
            if key == "Server" || key == "server" {
                server = value.to_str().unwrap_or_else(|err| {
                    warn!(format!("err occured : {}", err.to_string()));
                    "ERR"
                });
            }
        }

        let data = format!("{d} : [{}]", server);
        info!(data);
        handle_data!(data, String);
        return Some(d.to_string());
    }

    return None;
}

/// get the favicon for a domain
pub async fn get_favicon(domain: String) -> Option<String> {
    let new_url = request::urljoin(domain.clone(), "/favicon.ico".to_string());
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
            warn!(format!("could not find favicon for {}", domain.clone()));
            return None;
        }
    }
}
