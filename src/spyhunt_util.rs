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

/* [FOR TESTING]
 * All functions must return a Option<()>.
 * No need to return data, redundant.
 *
 * [INFO]
 * Some functions take in Vec<T> where T = &str | String.
 * Most just take in a String | &str
 * I should fix that to be more uniform?
 */

use std::process::exit;

use futures::{future, task::waker};
use reqwest::Client;

use crate::{
    cmd_handlers::{self, cmd_info, run_cmd, run_cmd_string, run_piped_strings},
    file_util::{file_exists, read_from_file},
    google_search, handle_deps,
    request::{self, urljoin},
    save_util,
    user_agents::{self, get_user_agent_prexisting},
};

// above all
use {
    crate::file_util,
    base64::{
        alphabet,
        engine::{self, general_purpose},
        Engine as _,
    },
    cidr::Ipv4Cidr,
    colored::Colorize,
    dns_lookup::lookup_addr,
    murmur3::murmur3_32,
    murmur3::murmur3_x64_128,
    rand::random,
    rayon::prelude::*,
    reqwest::{dns::Resolve, header, ClientBuilder, Response},
    reqwest::{header::HeaderMap, StatusCode},
    reqwest::{header::HeaderValue, Proxy},
    serde::{de::IntoDeserializer, Deserializer},
    serde_json::to_vec,
    shodan_client::*,
    soup::pattern,
    soup::pattern::Pattern,
    std::net::ToSocketAddrs,
    std::{clone, process::Output},
    std::{
        collections::HashMap,
        error::Error,
        fmt::format,
        io::{BufRead, Stdin},
        net::{IpAddr, SocketAddr},
        path::{self, Path, PathBuf},
        str::{FromStr, SplitTerminator},
        string,
        sync::{Arc, Mutex},
    },
    strip_ansi_escapes,
    tokio_stream::{self as stream, StreamExt},
};

/// take a target string
/// and return a domain if the target isn't a file
/// or doesn't contain domains
pub fn parse_for_domains(file_or_domain: String) -> Vec<String> {
    let mut domains: Vec<String> = vec![];
    if file_util::file_exists(&file_or_domain) {
        match file_util::read_from_file(file_or_domain.clone()) {
            Ok(res) => {
                res.into_iter().for_each(|d| {
                    domains.push(d);
                });
            }
            Err(..) => {
                warn!(format!(
                    "file {} exits but failed to read, Treating it as a domain...",
                    file_or_domain.clone()
                ));
                domains = vec![file_or_domain];
            }
        };
    } else {
        domains = vec![file_or_domain];
    }

    return domains;
}

/// get the domain name for the ip [ip] [Completed]
/// # Example
/// ```rust
/// get_reverse_ip(["8.8.8.8"].to_vec());
/// ```
pub fn get_reverse_ip(ip: Vec<&str>) -> Option<()> {
    for d in ip {
        write_info!("[Reverse ip]");
        let ip_addr: Result<IpAddr, _> = d.parse();
        match ip_addr {
            Ok(data) => {
                match dns_lookup::lookup_addr(&data) {
                    Ok(d_name) => {
                        write_info_and_print!(" |-{} {}", d, d_name);
                    }
                    _ => {
                        warn!(format!("{d} : Could not get domain name"));
                        return None;
                    }
                };
            }
            _ => {
                warn!(format!("{d} : is not a valid ip"));
                return None;
                continue;
            }
        };
    }
    Some(())
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
                write_info_and_print!(" |- {}", domain.to_string());
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

            write_info_and_print!(" |-{}", entry);
        }
    }
}

// pub async fn shodan_api_tokio(api_key: String, domains: Vec<String>) {
//     domains.into_iter().map(|domain| async move {
//         let api = api_key.clone();
//         shodan_api(api, domain, false).await;
//     });
// }

/// find subdomains in a domain from [completed]
pub async fn subdomain_finder(domain: Vec<String>) -> Option<()> {
    // let deps_path = handle_deps::check_or_clone_spyhuntrs_deps();
    // let certsh_path = format!("{deps_path}/scripts/certsh.sh");
    // let spotter_path = format!("{deps_path}/scripts/spotter.sh");
    //
    // if !file_exists(&certsh_path) || !file_exists(&spotter_path) {
    //     err!(format!(
    //         "{} or {} does not exist",
    //         certsh_path, spotter_path
    //     ));
    // };

    // run subfinder -d {domain} -silent
    for d in &domain {
        match cmd_handlers::run_cmd_string(format!("subfinder -d {} -silent", d)) {
            Some(data) => {
                match data.stdout {
                    Some(x) => {
                        write_info_and_print!("[DOMAIN SCAN]");
                        for i in x.split('\n').into_iter() {
                            if !i.is_empty() {
                                write_info_and_print!(" |- {}", i);
                            }
                        }
                        write_info_and_print!(" *");
                    }
                    None => warn!(format!("{d} : error occured")),
                };
            }
            None => warn!(format!("{d} : error occured")),
        }
    }

    // closure to run scripts
    // let run_scripts = |str1: String| {
    //     for d in &domain {
    //         match cmd_handlers::run_piped_strings(format!("{str1} {d}"), "uniq".to_string()) {
    //             Some(data) => {
    //                 match data.stdout {
    //                     Some(x) => {
    //                         for i in x.split('\n').into_iter() {
    //                             if !i.is_empty() {
    //                                 info!(format!("{}", i));
    //                                 handle_data!(i, &str);
    //                             }
    //                         }
    //                     }
    //                     None => warn!(format!("{d} : error occured")),
    //                 };
    //             }
    //             None => warn!(format!("{d} : error occured")),
    //         }
    //     }
    // };
    info!("Running Scripts...");
    // run spotter [ this doesn't work ]
    // run_scripts(format!("bash {spotter_path}"));
    // run certsh [ this i moved below]
    // run_scripts(format!("bash {certsh_path}"));

    // using commmand
    for d in &domain {
        match cmd_handlers::run_bash(format!(
            r#"curl -s https://crt.sh/?Identity=%.{d} | grep ">*.{d}" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*{d}" | sort -u | awk 'NF'"#
        )) {
            Some(data) => {
                match data.stdout {
                    Some(x) => {
                        for i in x.split('\n').into_iter() {
                            if !i.is_empty() {
                                write_info_and_print!(" |- {}", i);
                            }
                        }
                        write_info_and_print!(" *");
                    }
                    None => warn!(format!("{d} : error occured")),
                };
            }
            None => warn!(format!("{d} : error occured")),
        }
    }

    Some(())
}

/// perform a webcrawl using hakrawler [completed]
pub fn webcrawler(domain: Vec<String>) -> Option<()> {
    for d in domain {
        let cmd = cmd_handlers::run_piped_strings(format!("echo {}", d), format!("hakrawler"));
        match cmd {
            Some(data) => {
                match data.stdout {
                    Some(x) => {
                        let _vec = x.split('\n').collect::<Vec<_>>();
                        if _vec.is_empty() {
                            write_info_and_print!(" |- no data gotten from hakrawler\n *");
                        } else {
                            for i in &_vec {
                                write_info_and_print!(" |-{}", i);
                            }
                            write_info_and_print!(" *");
                        }
                    }
                    None => {
                        warn!(format!("{d} : error occured"));
                        return None;
                    }
                };
            }
            None => {
                warn!(format!("{d} : error occured"));
                return None;
            }
        }
    }
    Some(())
}

/// get status code of domain using httpx [completed]
pub fn status_code(domain: &str) -> Option<()> {
    let xmd = cmd_handlers::run_piped_strings(
        format!("echo {}", domain),
        "httpx -silent -status-code".to_string(),
    );

    match xmd {
        Some(data) => {
            match data.stdout {
                Some(x) => {
                    write_info_and_print!(" |-{}\n", x);
                }
                None => match data.stderr {
                    Some(y) => {
                        warn!(format!("{domain} : {y}"));
                    }
                    _ => {
                        warn!(format!("{domain} : httpx failed to get stdout"));
                        return None;
                    }
                },
            };
        }
        None => {
            warn!(format!("{domain} : error occured on httpx"));
            return None;
        }
    }

    //
    // match xmd {
    //     Some(srt) => {
    //         let x = srt
    //             .stdout
    //             .clone()
    //             .unwrap_or_else(|| format!("{domain} [err]"));
    //         info!(x);
    //         handle_data!(x, );
    //     }
    //     _ => warn!(format!("err occured for {domain}")),
    // }
    Some(())
}

/// get status code of domain using reqwest [completed]
pub mod status_code {
    use crate::{request, save_util};
    use colored::Colorize;
    use futures::{future, SinkExt};
    use rayon::prelude::*;
    use reqwest;

    use super::status_code;

    /// get status code of domain using reqwest [completed]
    pub async fn status_code_reqwest(domain: String) -> Option<()> {
        let d = domain.trim().replace("https://", "").replace("http://", "");
        let mut code: u16 = 0;
        let resp = fetch_url!(domain.to_string());
        match resp {
            Ok(data) => {
                write_info_and_print!(" |- {} [{}]", d, data.status().as_u16());
            }
            Err(_) => {
                warn!("{} [no infomation]", d);
                return None;
            }
        };
        Some(())
    }

    pub async fn run_status_code_tokio(domains: Vec<String>) {
        let tasks = domains.clone().into_iter().map(|domain| {
            tokio::spawn(async move {
                status_code_reqwest(domain.clone()).await;
            })
        });

        future::join_all(tasks).await;
    }

    pub fn rayon_status_code_wrapper(domain: String) -> Option<()> {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(status_code_reqwest(domain))
    }

    pub fn rayon_status_code(domains: Vec<String>) {
        domains.par_iter().for_each(|domain| {
            rayon_status_code_wrapper(domain.to_string());
        })
    }
}

pub mod enumerate_domain {
    use crate::{request, save_util};
    use colored::Colorize;
    use futures::future;
    use reqwest::{self, Client, Response};

    /// enumate domain for server info and ip [completed]
    pub async fn enumerate_domain(domain: String) -> Option<()> {
        let mut server: &str = "unknown";

        let mut resp: Response;
        match fetch_url!(domain.to_string()) {
            Ok(r) => resp = r,
            Err(err) => {
                warn!(format!("Err : {err}"));
                return None;
            }
        };

        let mut domain_ip: String = String::new();

        match dns_lookup::lookup_host(
            domain
                .trim()
                .replace("https://", "")
                .replace("http://", "")
                .as_str(),
        ) {
            Ok(ips) => {
                match Some(ips) {
                    Some(ip) => {
                        match ip.get(0) {
                            Some(v4) => {
                                domain_ip = v4.to_string();
                            }
                            _ => {
                                warn!(format!(
                                    "could not parse data gotten from lookup for {}",
                                    domain
                                ));
                                return None;
                            }
                        };
                    }
                    _ => {
                        warn!(format!("no ip gotten for {}", domain));
                    }
                };
            }
            _ => (),
        };

        if domain_ip.is_empty() {
            domain_ip = "Could not resolve ip".to_string();
        }

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

            let data = format!("{d} [{domain_ip}] : [{server}]");
            write_info_and_print!(" |-{}", data);
            return Some(());
        }

        return None;
    }

    pub async fn enumerate_domain_tokio(domains: Vec<String>) {
        let tasks = domains.into_iter().map(|domain| {
            tokio::spawn(async move {
                enumerate_domain(domain).await;
            })
        });

        future::join_all(tasks).await;
    }
}

/// get the favicon hash for a domain [completed]
/// # Issue
/// dunno how this works ?
/// maybe just get the image and look ??
/// because it could have been changed? plus hashes don't match
pub async fn get_favicon_hash(domain: String) -> Option<()> {
    let new_url = request::urljoin(domain.clone(), "/favicon.ico".to_string());
    let resp = fetch_url!(new_url.clone());
    //println!("{:#?}", resp);
    match resp {
        Ok(body) => {
            if body.status().is_success() {
                let mut base_64 = general_purpose::STANDARD.encode(body.bytes().await.unwrap());
                // let hash = murmur3_32(&mut std::io::Cursor::new(base_64), 0).unwrap();
                let hash = (murmurhash3::murmurhash3_x86_32(base_64.as_bytes(), 0)) as i32;
                //   println!("hash :{hash}");
                write_info_and_print!(" |-{} favicon hash : [{}]", domain, hash);
                return Some(());
            } else {
                warn!(format!("could not find favicon for {}", domain.clone()));
                return None;
            }
        }
        _ => {
            warn!(format!("could not find favicon for {}", domain.clone()));
            return None;
        }
    }
}

pub mod check_cors_misconfig {
    use {
        crate::{request, save_util},
        colored::Colorize,
        futures::future,
        rayon::prelude::*,
        reqwest::{self},
        std::time::Duration,
    };
    /// checks for cors misconfiguration for a domain [completed]
    /// # Example
    /// ```rust
    /// check_cors_misconfig("www.example.com");
    /// ```
    /// # panic
    /// will panic if its unable to create a client
    pub async fn check_cors_misconfig(domain: String) -> () {
        let payload = format!("{domain}, evil.com");

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(std::time::Duration::new(5, 0))
            .build()
            .unwrap_or_else(|err| {
                warn!(format!("unable to create Client Session\n{}", err));
                panic!();
            });

        // Prepare headers
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::ORIGIN, payload.parse().unwrap());

        // Make the request
        let mut resp: reqwest::Response;
        match client
            .get(request::urljoin(domain.to_string(), "".to_string()))
            .headers(headers)
            .send()
            .await
        {
            Ok(response) => {
                resp = response;
            }
            _ => {
                warn!(format!("request to {domain} failed"));
                return ();
            }
        };

        //println!("{:#?}", resp);

        let (mut allow_origin, mut allow_method): (bool, bool) = (false, false);
        match resp.headers().get("Access-Control-Allow-Origin") {
            Some(value) => {
                if value.to_str().unwrap_or_else(|_| "") == "evil.com" {
                    allow_origin = false;
                }
            }
            None => (),
        };

        match resp.headers().get("Access-Control-Allow-Credentials") {
            Some(value) => {
                if value.to_str().unwrap_or_else(|_| "") == "true" {
                    allow_origin = false;
                }
            }
            None => (),
        };
        let mut vuln_status: String;
        if allow_origin && allow_method {
            vuln_status = "VULNERABLE".to_string();
        } else {
            vuln_status = "NOT VULNERABLE".to_string();
        }
        write_info_and_print!(" |-[{}] {}", vuln_status, domain);
    }

    /// checks for cors misconfiguration in parallel using rayon [completed]
    // pub fn run_cors_misconfig_threads(domains: Vec<String>) -> () {
    //     domains.par_iter().for_each(|domain| {
    //         {
    //             info!(format!("Checking CORS for {}", domain));
    //             //std::thread::sleep(std::time::Duration::from_secs(1));
    //             check_cors_misconfig(domain.to_string()).await;
    //             info!(format!("Checked: {}", domain));
    //         }
    //     });
    // }

    pub async fn run_cors_misconfig_tokio(domains: Vec<String>) {
        let tasks = domains.into_iter().map(|domain| {
            tokio::spawn(async move {
                check_cors_misconfig(domain).await;
            })
        });

        future::join_all(tasks).await;
    }
}

/// you can either pass in a [proxy] or a [proxy file name] as the [proxy]
/// but you need to specify if its a proxy_file using the boolean [is_proxy_file]
/// need fix [completed]
/// # example
/// ```rust
/// let x : Vec<String> = setup_proxies("socks5://127.0.0.1:8095",false).unwrap;
/// let y : Vec<String> = setup_proxies("proxies.txt",true).unwrap;
/// ```
pub fn setup_proxies(proxy: String, is_proxy_file: bool) -> Option<Vec<String>> {
    let mut proxies: Vec<String> = vec![];
    let mut ret_proxies: Vec<String> = vec![];

    if proxy.is_empty() {
        return None;
    }

    if is_proxy_file {
        match read_from_file(proxy) {
            Ok(data) => {
                proxies = data.clone();
            }
            Err(_) => return None,
        };
    } else {
        proxies.push(proxy);
    };

    let protocols = vec!["http://", "https://", "socks4://", "socks5://"];
    let mut trip = false;
    for __proxy in proxies {
        for __protocol in &protocols {
            if __proxy.starts_with(__protocol) {
                trip = true;
            }
        }

        if trip {
            ret_proxies.push(__proxy);
        } else {
            ret_proxies.push(format!("http://{__proxy}"));
        }
        trip = false;
    }

    return Some(ret_proxies);
}

/// checks for host header injection for the domain [domain]
/// [proxy] & [proxyfile] is passed into [setup_proxies(...)] [completed]
/// # Example
/// ```rust
/// check_host_header_injection("www.example.com","proxies.txt",false);
/// check_host_header_injection("www.example.com","socks5://127.0.0.1:8095",false);
/// ```
pub async fn check_host_header_injection(domain: String, proxy: String, is_proxy_file: bool) {
    // Prepare headers
    let evil: HeaderValue = "evil.com".to_string().parse().unwrap();

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::HOST, evil.clone());
    headers.insert("X-Fowarded-Host", evil.clone());
    headers.insert("X-Fowarded-For", evil.clone());
    headers.insert("X-Client-Ip", evil.clone());
    headers.insert("X-Remote-Ip", evil.clone());
    headers.insert("X-Remote-Addr", evil.clone());
    headers.insert("X-Host", evil.clone());

    let proxy = setup_proxies(proxy, is_proxy_file).unwrap_or(Vec::new());

    let mut curr_proxy: Proxy;

    // this is ignored, throw an error if a proxy doesn't exist
    // if !proxy.is_empty() {
    //     curr_proxy = reqwest::Proxy::http(proxy[0].clone()).unwrap();
    // };
    //
    //

    // make this fetch a random proxy
    let client = if !proxy.is_empty() {
        info!("Using Proxy");
        curr_proxy = reqwest::Proxy::http(proxy[0].clone()).unwrap_or_else(|_| {
            err!("Failed to create Proxy");
        });
        reqwest::Client::builder()
            .proxy(curr_proxy)
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_else(|err| {
                err!(format!("unable to create Client Session\n{}", err));
            })
    } else {
        info!("No Proxy Configured");
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_else(|err| {
                warn!(format!("unable to create Client Session\n{}", err));
                panic!();
            })
    };
    let url = validate_url!(domain.clone());
    let normal_response_text: String = match client
        .get(url)
        .header(
            reqwest::header::USER_AGENT,
            user_agents::get_user_agent_prexisting()
                .parse::<HeaderValue>()
                .unwrap(),
        )
        .send()
        .await
    {
        Ok(t) => match t.text().await {
            Ok(_t) => _t,
            Err(_) => err!("ERR : Failed to get string"),
        },
        Err(err) => {
            if err.is_timeout() {
                err!("Request Timedout");
            }
            if err.is_request() {
                err!("Err from request");
            }
            if err.is_connect() {
                err!("Err from connection issue");
            }
            err!("Err {}", err);
            std::process::exit(1);
        }
    };

    for h in &headers {
        let resp = client
            .get(request::urljoin(domain.clone(), "".to_string()))
            .header(h.0, h.1)
            .send()
            .await;

        match &resp {
            Ok(response) => {
                match response.status().as_u16() {
                    301 | 302 | 303 | 307 | 308 => {
                        match response.headers().get(header::LOCATION) {
                            Some(headervalue) => {
                                match headervalue.to_str() {
                                    Ok(value) => {
                                        if value.to_lowercase() == "evil.com" {
                                            info!("vulnerable");
                                        }
                                    }
                                    Err(_) => {
                                        warn!(format!("{domain} : fetching string value from Location header failed"));
                                    }
                                };
                            }
                            _ => {
                                warn!(format!("{domain} : No Location header found"));
                            }
                        };
                    }
                    _ => {
                        warn!(format!("{domain} : response code not in scope"));
                    }
                };
            }
            _ => {
                warn!(format!("request to {domain} failed"));
            }
        }

        match resp {
            Ok(response) => match response.text().await {
                Ok(response_text) => {
                    if response_text != normal_response_text {
                        if response_text.to_lowercase().contains("evil.com") {
                            info!("vulnerable");
                        }
                    }
                }
                Err(_) => {
                    warn!(format!("{domain} : No text data found"));
                }
            },
            Err(_) => warn!(format!("{domain} : Failed to convert response to text")),
        }
    }
}

pub async fn check_security_headers(domain: String) {
    let security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
    ];

    let Session = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(std::time::Duration::new(5, 0))
        .build()
        .unwrap_or_else(|err| {
            warn!(format!("unable to create Client Session\n{}", err));
            panic!();
        });

    let mut no_sec: Vec<String> = vec![];
    let mut found_hd: Vec<String> = vec![];
    let mut no_dup: Vec<String> = vec![];
    let mut no_dup_found: Vec<String> = vec![];
    let resp = Session
        .get(request::urljoin(domain.clone(), "".to_string()))
        .send()
        .await;

    match resp {
        Ok(data) => {
            let __headers = data.headers().clone();

            for (key, value) in __headers {
                let h = key.unwrap().as_str().to_string();
                match h.to_lowercase().as_str() {
                    "strict-transport-security" => {
                        write_info_and_print!(
                            " |-{} : Found Security Header {}",
                            domain,
                            security_headers[0]
                        );
                    }
                    "content-security-policy" => {
                        write_info_and_print!(
                            " |-{} : Found Security Header {}",
                            domain,
                            security_headers[0]
                        );
                    }
                    "x-frame-options" => {
                        write_info_and_print!(
                            " |-{} : Found Security Header {}",
                            domain,
                            security_headers[0]
                        );
                    }
                    "x-content-type-options" => {
                        write_info_and_print!(
                            " |-{} : Found Security Header {}",
                            domain,
                            security_headers[0]
                        );
                    }
                    "x-xss-protection" => {
                        write_info_and_print!(
                            " |-{} : Found Security Header {}",
                            domain,
                            security_headers[0]
                        );
                    }
                    _ => {}
                }
            }
        }
        Err(_) => {
            warn!(format!("{domain}: failed to make request"));
        }
    }
}

/// run network analyzer using shodan
///
pub fn network_analyzer(domain: String) {
    match run_cmd_string(format!("shodan stats --facets port net:{}", domain)) {
        Some(data) => match data.stdout {
            Some(out) => {
                write_info_and_print!("{}", out);
            }
            _ => match data.stderr {
                Some(out) => warn!(format!("stderr : {out}")),
                _ => {
                    warn!(format!(
                        "running shodan on {} failed, no output",
                        domain.clone()
                    ));
                }
            },
        },
        _ => {
            warn!(format!("running shodan on {} failed", domain.clone()));
        }
    };

    match run_cmd_string(format!("shodan stats --facets vuln net:{}", domain)) {
        Some(data) => match data.stdout {
            Some(out) => {
                write_info_and_print!("{}", out);
            }
            _ => match data.stderr {
                Some(out) => warn!(format!("stderr : {out}")),
                _ => {
                    warn!(format!(
                        "running shodan on {} failed, no output",
                        domain.clone()
                    ));
                }
            },
        },
        _ => {
            warn!(format!("running shodan on {} failed", domain.clone()));
        }
    };
}

/// run waybackurl on [domain]
pub fn wayback_urls(domain: String) {
    match run_piped_strings(format!("waybackurls {}", domain), format!("anew")) {
        Some(data) => match data.stdout {
            Some(out) => {
                write_info_and_print!("{}", out);
            }
            _ => match data.stderr {
                Some(out) => warn!(format!("stderr : {out}")),
                _ => {
                    warn!(format!(
                        "running waybackurls on {} failed, no output",
                        domain.clone()
                    ));
                }
            },
        },
        _ => {
            warn!(format!("running waybackurls on {} failed", domain.clone()));
        }
    };
}

/// a namespace for javascript functions
pub mod javascript {
    use {
        crate::{request, save_util},
        colored::Colorize,
        futures::{SinkExt, StreamExt},
        rayon::iter::{IntoParallelRefIterator, ParallelIterator},
        reqwest::Url,
        scraper::selectable::Selectable,
        std::{collections::HashMap, hash::Hash},
    };

    pub fn is_valid_url(url: String) -> bool {
        match reqwest::Url::parse(url.as_str()) {
            Ok(_) => true,
            _ => false,
        }
    }

    pub fn is_same_domain(url: String, domain: String) -> bool {
        match reqwest::Url::parse(url.as_str()) {
            Ok(_url) => match _url.domain() {
                Some(_domain) => {
                    if domain == _domain.to_string() {
                        return true;
                    }
                }
                _ => {
                    return false;
                }
            },
            Err(err) => return false,
        }
        false
    }

    pub async fn get_js_links(url: String, Domain: Option<String>) -> (Vec<String>, Vec<String>) {
        let session = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(2))
            .timeout(std::time::Duration::new(10, 0))
            .build()
            .unwrap_or_else(|err| {
                warn!(format!("unable to create Client Session\n{}", err));
                panic!();
            });
        // if no domain, exit
        let domain = match Domain {
            Some(d) => d,
            None => return (vec![], vec![]),
        };

        let mut html = String::new();
        match session.get(url.clone()).send().await {
            Ok(resp) => match resp.text().await {
                Ok(text) => html = text.to_owned(),

                Err(_) => {
                    warn!(format!("Failed to data from {url}"));
                    return (vec![], vec![]);
                }
            },
            Err(err) => {
                if err.is_timeout() {
                    warn!(format!("Err {url} Timedout"));
                }
            }
        };
        let mut js_files: Vec<String> = Vec::new();
        let document = scraper::Html::parse_document(&html);
        let script_selector = scraper::Selector::parse("script").unwrap();

        // Find all <script> tags with src attributes
        for element in document.select(&script_selector) {
            if let Some(src) = element.value().attr("src") {
                if let Ok(script_url) =
                    reqwest::Url::parse(url.clone().as_str()).and_then(|base| base.join(src))
                {
                    js_files.push(script_url.to_string());
                }
            }
        }

        let js_in_script_re = regex::Regex::new(r#"[\'\"]([^\'\"]*\.js)[\'\"]"#).unwrap();

        // Find JavaScript files in using regex
        for script in document.select(&script_selector) {
            if let Some(val) = script.text().next() {
                for i in js_in_script_re.captures_iter(val) {
                    if let Some(__url) = i.get(1) {
                        let full_url = match reqwest::Url::parse(url.clone().as_str())
                            .unwrap()
                            .join(__url.as_str())
                        {
                            Ok(ok_data) => ok_data,
                            Err(_) => continue,
                        };

                        if is_valid_url(full_url.to_string())
                            && is_same_domain(url.clone(), full_url.to_string())
                        {
                            js_files.push(full_url.to_string().clone());
                        }
                    }
                }
            }
        }
        let mut newlinks: Vec<String> = Vec::new();
        let a_tags = scraper::Selector::parse("a[href]").unwrap();

        let base_url = reqwest::Url::parse(url.as_str()).unwrap();

        for element in document.select(&a_tags) {
            if let Some(href) = element.value().attr("href") {
                // damn i didn't know you could do if Ok(val) = x {}
                if let Ok(full_url) = base_url.join(href) {
                    newlinks.push(full_url.to_string());
                }
            }
        }
        return (js_files, newlinks);
    }

    pub fn get_js_links_async_wrapper(
        url: String,
        Domain: Option<String>,
    ) -> (Vec<String>, Vec<String>) {
        let _runtime = tokio::runtime::Runtime::new().unwrap();
        _runtime.block_on(get_js_links(url, Domain))
    }

    /// Takes a Vec of Urls
    /// - Finds the domain
    /// - Searches through the url to find js Links and js Files
    /// - prints them out
    ///
    /// Takes Vec of urls because it runs multithreading
    pub async fn crawl_website(urls: Vec<String>) -> Option<()> {
        /*
         * i will use tokio::Semaphore later when i grasp it
         */
        if urls.is_empty() {
            return None;
        }

        // let results: Vec<HashMap<&String, (Vec<String>, Vec<String>)>> = urls
        //     .par_iter()
        //     .filter_map(|url| {
        //         let domain: Option<String> = match reqwest::Url::parse(url.as_str()) {
        //             Ok(_url) => match _url.domain() {
        //                 Some(d) => Some(d.to_string()),
        //                 _ => None,
        //             },
        //             Err(_) => None,
        //         };
        //         let data =
        //             get_js_links_async_wrapper(url.to_string(), Some("".to_string()).clone());
        //         Some(HashMap::from([(url, (data))]))
        //     })
        //     .collect();

        let mut url_stream = tokio_stream::iter(urls.clone());
        let mut handles = Vec::new();

        while let Some(url) = url_stream.next().await {
            let url = url.clone();
            let handle = tokio::task::spawn(async move {
                let domain = reqwest::Url::parse(&url)
                    .ok()
                    .and_then(|parsed_url| parsed_url.domain().map(|d| d.to_string()));

                let _url = validate_url!(url);

                let data = get_js_links(_url.clone(), domain).await;

                HashMap::from([(url.clone(), data)])
            });
            handles.push(handle);
        }

        let results: Vec<HashMap<String, (Vec<String>, Vec<String>)>> =
            futures::future::join_all(handles)
                .await
                .into_iter()
                .filter_map(|res| res.ok())
                .collect();
        if !results.is_empty() {
            if results[0].is_empty() {
                info!("No JavaScript files found");
            } else {
                info!("[JavaScript files]");
            }
            for hashmap in results {
                for (url, vecs) in hashmap {
                    write_info_and_print!(" |- [URL] {}", url);
                    if vecs.0.is_empty() {
                        write_info_and_print!(" |- {}", "No javascript files found".red());
                        write_info_and_print!(" *");
                    } else {
                        write_info_and_print!(" |- {}", "[Javascript Files]".green());
                        for _js_files in vecs.0 {
                            if !_js_files.is_empty() {
                                write_info_and_print!(" |- {}", _js_files);
                            }
                        }
                        write_info_and_print!(" *");
                    }
                    if vecs.1.is_empty() {
                        write_info_and_print!(" |- {}", "No javascript links found".red());
                        write_info_and_print!(" *");
                    } else {
                        write_info_and_print!(" |- {}", "[Javascript Links]".green());
                        for _js_links in vecs.1 {
                            if !_js_links.is_empty() {
                                write_info_and_print!(" |- {}", _js_links);
                            }
                        }
                        write_info_and_print!(" *");
                    }
                }
            }
        }
        return Some(());
    }
}

/// run a dns scan on domain
pub fn dns(domain: String) {
    let commands: Vec<_> = vec!["-ns -resp", "-cname -resp", "-a -resp"];
    let mut place = 0;
    for cmd in &commands {
        match place {
            0 => {
                write_info_and_print!("{} [A records]", domain);
            }
            1 => {
                info!("Printing NS records");
                write_info_and_print!("{} [NS records]", domain);
            }
            2 => {
                info!("Printing CNAME records");
                write_info_and_print!("{} [CNAME records]", domain);
            }
            _ => {}
        };
        match run_piped_strings(format!("echo {}", domain), format!("dnsx -silent {}", cmd)) {
            Some(data) => match data.stdout {
                Some(out) => {
                    let out_vec = out.split("\n").collect::<Vec<&str>>();
                    for i in out_vec {
                        if !i.is_empty() {
                            write_info_and_print!(" |-{i}");
                        } else {
                            write_info_and_print!(" |-No More record found\n *");
                        }
                    }
                }
                _ => match data.stderr {
                    Some(out) => warn!(format!("stderr : {out}")),
                    _ => {
                        warn!(format!(
                            "running dnsx on {} failed, no output",
                            domain.clone()
                        ));
                    }
                },
            },
            _ => {
                warn!(format!("running dnsx on {} failed", domain.clone()));
            }
        };
        place += 1;
    }
}

/// run httpprobe on domain
pub fn probe(domain: String) {
    match run_piped_strings(format!("echo {}", domain), format!("httprobe -c 100")) {
        Some(data) => {
            // match data.output { Some(opt) => {
            //
            //     }
            //     None => {}
            // };
            match data.stdout {
                Some(out) => {
                    match run_piped_strings(format!("echo {}", out), format!("anew")) {
                        Some(resp) => {
                            match resp.stdout {
                                Some(_stdout) => {
                                    info!(format!("{_stdout}"));
                                    write_info_and_print!("{}", _stdout);
                                }
                                None => match data.stderr {
                                    Some(_stderr) => warn!(format!("stderr : {_stderr}")),
                                    _ => {
                                        warn!(format!(
                                            "{} : running anew on httprobe output failed, could not get any output",
                                            domain.clone()
                                        ));
                                    }
                                },
                            };
                        }
                        None => {
                            warn!(format!(
                                "{} : running anew on httprobe output failed",
                                domain.clone()
                            ));
                        }
                    };
                }
                _ => match data.stderr {
                    Some(out) => warn!(format!("stderr : {out}")),
                    _ => {
                        warn!(format!(
                            "running httprobe on {} failed, no output",
                            domain.clone()
                        ));
                    }
                },
            }
        }
        _ => {
            warn!(format!(
                "running running httprobe on {} failed",
                domain.clone()
            ));
        }
    };
}

/// run httpx to check redirects on [domain]
pub fn redirects(domain: String) {
    match run_piped_strings(
        format!("echo {}", domain),
        format!("httpx -silent -location  -mc 301,302"),
    ) {
        Some(data) => {
            // match data.output { Some(opt) => {
            //
            //     }
            //     None => {}
            // };
            match data.stdout {
                Some(out) => {
                    match run_piped_strings(format!("echo {}", out), format!("anew")) {
                        Some(resp) => {
                            match resp.stdout {
                                Some(_stdout) => {
                                    let _vec = _stdout.split('\n').collect::<Vec<_>>();
                                    if _vec.is_empty() {
                                        write_info_and_print!(" |- no info from httpx\n *");
                                    } else {
                                        for i in &_vec {
                                            write_info_and_print!(" |- {}", i);
                                        }
                                        write_info_and_print!(" *");
                                    }
                                }
                                None => match data.stderr {
                                    Some(_stderr) => warn!(format!("stderr : {_stderr}")),
                                    _ => {
                                        warn!(format!(
                                            "{} : running anew on httpx output failed, could not get any output",
                                            domain.clone()
                                        ));
                                    }
                                },
                            };
                        }
                        None => {
                            warn!(format!(
                                "{} : running anew on httpx output failed",
                                domain.clone()
                            ));
                        }
                    };
                }
                _ => match data.stderr {
                    Some(out) => warn!(format!("stderr : {out}")),
                    _ => {
                        warn!(format!(
                            "running httpx on {} failed, no output",
                            domain.clone()
                        ));
                    }
                },
            }
        }
        _ => {
            warn!(format!(
                "running running httpx on {} failed",
                domain.clone()
            ));
        }
    };
}

/// check for broken links on [domain] using blc
pub fn brokenlinks(domain: String) {
    match run_cmd_string(format!(
        "blc -r --filter-level 2 {}",
        request::urljoin(domain.clone(), "".to_string())
    )) {
        Some(data) => match data.stdout {
            Some(out) => {
                write_info_and_print!(" |- {}", out);
            }
            _ => match data.stderr {
                Some(out) => warn!(format!("stderr : {out}")),
                _ => {
                    warn!(format!(
                        "running blc on {} failed, no output",
                        domain.clone()
                    ));
                }
            },
        },
        _ => {
            warn!(format!("running blc on {} failed", domain.clone()));
        }
    }
}

pub mod tech {
    use crate::request;
    use crate::save_util;
    use rayon::iter::IntoParallelRefIterator;
    use rayon::iter::ParallelIterator;
    use reqwest::Error;
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Debug)]
    pub struct ApiResponse {
        pub first: i64,
        pub last: i64,
        pub domain: String,
        pub groups: Vec<Group>,
    }

    #[derive(Deserialize, Debug)]
    pub struct Group {
        pub name: String,
        pub live: i32,
        pub dead: i32,
        pub latest: i64,
        pub oldest: i64,
        pub categories: Vec<Category>,
    }

    #[derive(Deserialize, Debug)]
    pub struct Category {
        pub live: i32,
        pub dead: i32,
        pub latest: i64,
        pub oldest: i64,
        pub name: String,
    }

    use colored::Colorize;
    /// find technology used in domain, using free api builtwith.com
    /// [completed]
    pub async fn find_tech(domain: String) {
        // publish a builtwith rs and use it
        let url = format!("https://api.builtwith.com/free1/api.json?KEY=d6c5879a-905a-4ba1-b82d-aad6576f93c3&LOOKUP={}",domain);
        println!("{url}");
        let Session = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(std::time::Duration::new(5, 0))
            .build()
            .unwrap_or_else(|err| {
                warn!(format!("unable to create Client Session\n{}", err));
                panic!();
            });

        let resp = Session.get(url).send().await;
        match resp {
            Ok(json) => match json.json::<ApiResponse>().await {
                Ok(ds) => {
                    write_info_and_print!("[TECH] : {}", domain);
                    if ds.groups.is_empty() {
                        write_info_and_print!("  |- no information on site");
                        write_info_and_print!("  *");
                    } else {
                        for i in &ds.groups {
                            write_info_and_print!(" |-{}", i.name);
                            if !i.categories.is_empty() {
                                for j in &i.categories {
                                    write_info_and_print!("  |-{}", i.name);
                                }
                            } else {
                                write_info_and_print!("  |- tech found");
                                write_info_and_print!("  *");
                            }
                        }
                    }
                }
                Err(_) => {
                    warn!(format!("{domain} : error parsing json, No data recieved, check network or domain name"));
                }
            },
            Err(_) => {
                warn!(format!(
                    "{domain} : error occured fetching data from builtwith.com"
                ));
            }
        };
    }
    pub fn find_tech_async_wrapper(domain: String) {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(find_tech(domain));
    }

    pub fn find_tech_main(domains: Vec<String>) {
        domains.par_iter().for_each(|domain| {
            find_tech_async_wrapper(domain.clone());
        });
    }
}

pub fn smuggler(domain: String) {}

/// get ip for domain [domain]
pub fn ip_addresses(domain: Vec<String>) -> Option<()> {
    for d in &domain {
        let ips: Option<Vec<_>> = match dns_lookup::lookup_host(d) {
            Ok(ips) => Some(ips),
            _ => None,
        };
        match ips {
            Some(ip) => {
                match ip.get(0) {
                    Some(v4) => {
                        let ip_v4 = v4.to_string();
                        write_info_and_print!(" |-{} : [{}]", d, ip_v4);
                    }
                    _ => {
                        warn!(format!("could not parse data gotten from lookup for {}", d));
                        return None;
                    }
                };
            }
            _ => {
                warn!(format!("no ip gotten for {}", d));
                return None;
            }
        };
    }
    Some(())
}

/// This does exactly what `enumerate_domain(...)` does.
/// It literally just finds a title in the html
/// And Appends it, which would be better off just doing
/// That in `enumerate_domain(...)`
pub async fn domain_info(domain: Vec<String>) -> Option<()> {
    return Some(enumerate_domain::enumerate_domain_tokio(domain).await);
}

/// checks for important subdomains in a file or subdomains [completed]
pub fn importantsubdomains(subdomain_file: String) {
    if !file_exists(&subdomain_file) {
        err!(format!("{subdomain_file} not found"));
    }
    let mut importantsubs: Vec<&str> = vec![];
    let info: Vec<_> = vec![
        "admin", "dev", "test", "api", "staging", "prod", "beta", "manage", "jira", "github",
    ];
    match read_from_file(subdomain_file.clone()) {
        Ok(subs) => {
            for sub in &subs {
                for i in &info {
                    if sub.contains(i) {
                        importantsubs.push(sub);
                        break;
                    }
                }
            }
            write_info_and_print!("[IMPORTANT SUBDOMAINS]");
            if importantsubs.is_empty() {
                warn!("No important subdomain found");
                write_info!("No important subdomain found");
                return;
            }
            for i in importantsubs {
                write_info_and_print!("{}", i);
            }
        }
        Err(_) => {
            warn!(format!("error reading from file {subdomain_file}"));
        }
    };
}

/// finds all subdomains in the [domains_file] that returns a 404 [compeleted]
pub async fn find_not_found(domains_file: String) -> Option<()> {
    let mut not_found_domains: Vec<String> = vec![];
    let user_agent = get_user_agent_prexisting();
    let Session = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(std::time::Duration::new(5, 0))
        .user_agent(user_agent)
        .build()
        .unwrap_or_else(|err| {
            warn!(format!("unable to create Client Session\n{}", err));
            panic!();
        });

    if !file_exists(&domains_file) {
        err!("{} does not exist", domains_file);
    }

    match read_from_file(domains_file) {
        Ok(data) => {
            for sub in data {
                match Session.get(sub.clone()).send().await {
                    Ok(resp) => {
                        if resp.status().as_u16() == 404 {
                            not_found_domains.push(sub);
                        }
                    }
                    Err(_) => {
                        warn!(format!("{sub} : could not make request"));
                        return None;
                    }
                }
            }
        }
        Err(_) => {
            err!("Could not read from file provided");
            return None;
        }
    }
    if not_found_domains.is_empty() {
        warn!("No 404 subdomain found");
    } else {
        for sub in &not_found_domains {
            write_info_and_print!(" |-{sub} [NOT FOUND]");
        }
    }
    Some(())
}

/// run paramspider on domain [completed]
pub fn paramspider(domain: String) -> Option<()> {
    match run_cmd_string(format!("paramspider -d {domain}")) {
        Some(data) => match data.stdout {
            Some(out) => {
                write_info_and_print!(" |- {}", out);
                match data.stderr {
                    Some(out) => {
                        if out.contains("SyntaxWarning: invalid escape sequence") {
                            for line in out.split('\n').collect::<Vec<_>>() {
                                if line.contains("SyntaxWarning: invalid escape sequence") {
                                    continue;
                                }
                                if line.contains("[") {
                                    write_info_and_print!("{line}");
                                }
                            }
                        }
                    }
                    None => {}
                }
            }
            None => match data.stderr {
                Some(out) => warn!("stderr : {}", out),
                _ => {
                    warn!(
                        "running paramspider on {} failed, no output",
                        domain.clone()
                    );
                    return None;
                }
            },
        },
        _ => {
            warn!("running paramspider on {} failed", domain.clone());
            return None;
        }
    }
    Some(())
}

/// run nmap on ip or domain [completed]
pub fn nmap(domain: String) -> Option<()> {
    let ip = match run_cmd_string(format!("nmap -vvv {domain} -sV")) {
        Some(data) => match data.stdout {
            Some(out) => {
                write_info_and_print!("{}", out);
            }
            _ => match data.stderr {
                Some(out) => warn!("stderr : {}", out),
                _ => {
                    warn!("running nmap on {} failed, no output", domain.clone());
                    return None;
                }
            },
        },
        _ => {
            warn!("running nmap on {} failed", domain.clone());
            return None;
        }
    };
    Some(())
}

/// i dunno what it does that others don't do
pub mod api_fuzzer {
    use crate::spyhunt_util::future;
    use crate::{
        file_util::{self, file_exists, read_from_file},
        save_util,
        user_agents::get_user_agent_prexisting,
    };
    use crate::{handle_deps, request};
    use colored::Colorize;
    use reqwest;
    use std::collections::HashMap;
    use std::fmt::format;
    use tokio::sync::futures;

    pub async fn api_fuzzer(domain: String) -> Option<()> {
        let error_patterns: Vec<_> = vec![
            "404",
            "Page Not Found",
            "Not Found",
            "Error 404",
            "404 Not Found",
            "The page you requested was not found",
            "The requested URL was not found",
            "This page does not exist",
            "The requested page could not be found",
            "Sorry, we couldn't find that page",
            "Page doesn't exist",
        ];

        let user_agent = get_user_agent_prexisting();
        let Session = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(std::time::Duration::new(5, 0))
            .user_agent(user_agent)
            .build()
            .unwrap_or_else(|err| {
                warn!(format!("unable to create Client Session\n{}", err));
                panic!();
            });

        let deps_path = handle_deps::check_or_clone_spyhuntrs_deps();
        if !file_exists(&format!("{deps_path}/payloads/api-endpoints.txt")) {
            warn!("could not find spyhuntrs-deps : payloads/api-endpoints.txt, quitting....");
            return None;
        }

        let mut found_partterns: HashMap<String, String> = HashMap::new();
        let mut existing_endpoints: Vec<String> = vec![];
        let api_endpoints: Vec<String> =
            read_from_file(format!("{deps_path}/payloads/api-endpoints.txt")).unwrap();

        for endpoint in &api_endpoints {
            let url = request::urljoin(domain.clone(), endpoint.to_string());
            match Session.get(url.clone()).send().await {
                Ok(resp) => {
                    // get status code
                    match resp.status().as_u16() {
                        403 | 404 => {}
                        200 => {
                            existing_endpoints.push(url.clone());
                        }
                        _ => {}
                    };

                    // get pattern
                    let mut lower_text: String = String::new();
                    match resp.text().await {
                        Ok(text_data) => {
                            lower_text = text_data.to_lowercase();
                            for pattern in &error_patterns {
                                if lower_text.contains(pattern) {
                                    found_partterns
                                        .insert(endpoint.to_string(), pattern.to_string());
                                }
                            }
                        }
                        Err(_) => {}
                    };

                    // // see if title has some sort of 404
                    // let document = scraper::Html::parse_document(&lower_text.clone());
                    // // Define the title selector
                    // let title_selector = scraper::Selector::parse("title").unwrap();
                    //
                    // // Find the title element
                    // if let Some(title_element) = document.select(&title_selector).next() {
                    //     let title_text = title_element.text().collect::<String>().to_lowercase();
                    // }
                }
                Err(_) => {
                    warn!("{} : failed to fetch endpoint {}", domain, endpoint);
                }
            };
        }

        write_info_and_print!("[ENDPOINTS] {}", domain);
        if !existing_endpoints.is_empty() {
            for i in &existing_endpoints {
                write_info_and_print!(" |- {}", i);
            }
        } else {
            info!(" |- No endpoints found");
        }
        write_info_and_print!(" *");

        write_info_and_print!("[PARTTENS] {}", domain);
        if !found_partterns.is_empty() {
            for (k, v) in &found_partterns {
                write_info_and_print!(" |- Endpoint: {} - pattern: {}", k, v);
            }
        } else {
            info!(" |- No Patterns found");
        }
        write_info_and_print!(" *");

        Some(())
    }

    pub async fn api_fuzzer_tokio(domains: Vec<String>) {
        let tasks = domains.into_iter().map(|domain| {
            tokio::spawn(async move {
                api_fuzzer(domain).await;
            })
        });
        future::join_all(tasks).await;
    }
}

pub mod forbiddenpass {
    use {
        crate::{
            file_util::read_from_file, get_save_file, handle_deps, request::urljoin, save_util,
            user_agents::get_user_agent_prexisting,
        },
        colored::Colorize,
        rayon::str::ParallelString,
        reqwest::{
            self,
            header::{HeaderMap, HeaderName, HeaderValue, IntoHeaderName},
        },
        std::collections::HashMap,
    };

    /// creates a headerMap from an array of a Key,vaule pair of a header
    /// no i will not use hashmap
    fn create_header_map(additional_headers: [&str; 2]) -> HeaderMap {
        let (k, v): (String, String) = (
            additional_headers[0].to_string(),
            additional_headers[1].to_string(),
        );

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            get_user_agent_prexisting().parse().unwrap(),
        );
        headers.insert(
            k.parse::<HeaderName>().unwrap(),
            v.parse::<HeaderValue>().unwrap(),
        );

        headers
    }

    /// get a specific set of headers
    fn get_headers() -> Vec<HeaderMap> {
        let mut headers_list: Vec<HeaderMap> = Vec::new();

        let header_map_list = vec![
            create_header_map(["X-Custom-IP-Authorization", "127.0.0.1"].into()),
            create_header_map(("X-Forwarded-For", "http://127.0.0.1").into()),
            create_header_map(("X-Forwarded-For", "127.0.0.1:80").into()),
            create_header_map(("X-Originally-Forwarded-For", "127.0.0.1").into()),
            create_header_map(("X-Originating-", "http://127.0.0.1").into()),
            create_header_map(("X-Originating-IP", "127.0.0.1").into()),
            create_header_map(("True-Client-IP", "127.0.0.1").into()),
            create_header_map(("X-WAP-Profile", "127.0.0.1").into()),
            create_header_map(("X-Arbitrary", "http://127.0.0.1").into()),
            create_header_map(("X-HTTP-DestinationURL", "http://127.0.0.1").into()),
            create_header_map(("X-Forwarded-Proto", "http://127.0.0.1").into()),
            create_header_map(("Destination", "127.0.0.1").into()),
            create_header_map(("X-Remote-IP", "127.0.0.1").into()),
            create_header_map(("X-Client-IP", "http://127.0.0.1").into()),
            create_header_map(("X-Host", "http://127.0.0.1").into()),
            create_header_map(("X-Forwarded-Host", "http://127.0.0.1").into()),
            create_header_map(("X-Forwarded-Port", "4443").into()),
            create_header_map(("X-Forwarded-Port", "80").into()),
            create_header_map(("X-Forwarded-Port", "8080").into()),
            create_header_map(("X-Forwarded-Port", "8443").into()),
            create_header_map(("X-ProxyUser-Ip", "127.0.0.1").into()),
            create_header_map(("Client-IP", "127.0.0.1").into()),
        ];

        header_map_list
    }
    /// i have no idea what it does
    pub async fn forbiddenpass(domain: String) -> Option<()> {
        let deps_path = handle_deps::check_or_clone_spyhuntrs_deps();
        let wordlist = read_from_file(format!("{deps_path}/payloads/bypasses.txt"));

        let Session = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(std::time::Duration::new(5, 0))
            .build()
            .unwrap_or_else(|err| {
                warn!(format!("unable to create Client Session\n{}", err));
                panic!();
            });
        let url = urljoin(domain.clone(), "".to_string());
        let mut headers = get_headers();
        for header in &headers {
            match Session
                .get(url.clone())
                .headers(header.clone())
                .send()
                .await
            {
                Ok(resp) => match resp.status().as_u16() {
                    200 => {
                        write_info_and_print!(" |- {} [200] : {:#?}", domain, header);
                    }
                    _ => {}
                },
                Err(err) => {
                    if err.is_timeout() {
                        warn!("{}: request Timeout", domain);
                    } else {
                        warn!("{}: a request failed", domain);
                    }
                }
            }
        }
        Some(())
    }
} // mod forbiddenpass

// run directory bruteforce using reqwest on [domain]
// using [wordlist] with status code out of scope of [excluded_codes]
pub async fn directory_brute(
    domain: String,
    wordlist_file: String,
    excluded_codes: Vec<i32>,
) -> Option<()> {
    if !file_exists(&wordlist_file) {
        err!("{} does not exist", wordlist_file);
    }
    let wordlists = read_from_file(wordlist_file).unwrap_or_else(|err| {
        err!("ERR : {}", err);
    });
    let Session = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(std::time::Duration::new(5, 0))
        .build()
        .unwrap_or_else(|err| {
            warn!(format!("unable to create Client Session\n{}", err));
            panic!();
        });

    let mut header: HeaderMap = HeaderMap::new();
    header.insert(
        header::USER_AGENT,
        get_user_agent_prexisting().parse::<HeaderValue>().unwrap(),
    );

    let tasks = wordlists.clone().into_iter().map(|wordlist| {
        let _excluded_codes = excluded_codes.clone();
        let _domain = domain.clone();
        let _Session = Session.clone();
        tokio::spawn(async move {
            match _Session
                .get(request::urljoin(_domain.clone(), wordlist.clone()))
                .send()
                .await
            {
                Ok(resp) => {
                    if !wordlist.is_empty() {
                        match resp.status().as_u16() {
                            200 => {
                                if !_excluded_codes.contains(&200) {
                                    write_info_and_print!(" |-{} [200]", wordlist);
                                }
                            }
                            302 => {
                                if !_excluded_codes.contains(&302) {
                                    write_info_and_print!(" |-{} [302]", wordlist);
                                }
                            }
                            301 => {
                                if !_excluded_codes.contains(&301) {
                                    write_info_and_print!(" |-{} [301]", wordlist);
                                }
                            }
                            _ => {}
                        };
                    }
                }
                Err(err) => {
                    if err.is_timeout() {
                        warn!("{} Timedout", wordlist);
                    }
                }
            };
        })
    });

    future::join_all(tasks).await;

    // for word in &wordlist {
    //     match Session
    //         .get(request::urljoin(domain.clone(), word.clone()))
    //         .send()
    //         .await
    //     {
    //         Ok(resp) => {
    //             match resp.status().as_u16() {
    //                 200 => {
    //                     if !excluded_codes.contains(&200) {
    //                         write_info_and_print!(" |-{} [200]", word);
    //                     }
    //                 }
    //                 302 => {
    //                     if !excluded_codes.contains(&302) {
    //                         write_info_and_print!(" |-{} [302]", word);
    //                     }
    //                 }
    //                 301 => {
    //                     if !excluded_codes.contains(&301) {
    //                         write_info_and_print!(" |-{} [301]", word);
    //                     }
    //                 }
    //                 _ => {}
    //             };
    //         }
    //         Err(err) => {
    //             if err.is_timeout() {
    //                 warn!("{} Timedout", word);
    //             }
    //         }
    //     };
    // }
    Some(())
}

// pub fn directory_brute_async_wrapper(
//     domain: String,
//     wordlist: Vec<String>,
//     excluded_codes: Vec<i32>,
// ) -> Option<()> {
//     return tokio::runtime::Runtime::new()
//         .unwrap()
//         .block_on(directory_brute(domain, wordlist, excluded_codes));
// }
//
// pub async fn directory_brute_tokio(
//     domain: String,
//     wordlists: Vec<String>,
//     excluded_codes: Vec<i32>,
// ) {
//     let tasks = wordlists.clone().into_iter().map(|wordlist| {
//         let _excluded_codes = excluded_codes.clone();
//         tokio::spawn(async move {
//             directory_brute(domain.clone(), wordlist, _excluded_codes).await;
//         })
//     });
//
//     future::join_all(tasks).await;
// }

/// Runs directory bruteforce on [domain] using a wordlist file [wordlist_file]
/// and outputs all status codes out of [excluded_codes]
/// run in parallel using rayon [completed]
// pub fn run_directory_brute_threads(
//     domains: Vec<String>,
//     wordlist_file: String,
//     excluded_codes: Vec<i32>,
// ) -> () {
//     if !file_exists(&wordlist_file) {
//         err!("{} does not exist", wordlist_file);
//     }
//     let wordlists = read_from_file(wordlist_file).unwrap_or_else(|err| {
//         err!("ERR : {}", err);
//     });
//
//     domains.par_iter().for_each(|domain| {
//         {
//             info!(format!("Running Directory bruteforce for {}", domain));
//             //std::thread::sleep(std::time::Duration::from_secs(1));
//             directory_brute_async_wrapper(
//                 domain.to_string(),
//                 wordlists.clone(),
//                 excluded_codes.clone(),
//             );
//         }
//     });
// }

/// run local file inclusion on a target or domain [not compeleted? depends on implementation of
/// the cli]
pub fn nuclei_lfi() -> Option<()> {
    let vulnerability: Vec<String> = vec![];
    let mut input = String::new();
    println!("Do you want to scan a file or a single target?[f,t,file,target]:");
    std::io::stdin().read_line(&mut input).unwrap();
    let mut cmd: String = String::new();
    match input.to_lowercase().as_str() {
        "f" | "file" => {
            let mut filename = String::new();
            std::io::stdin().read_line(&mut filename).unwrap();
            info!(format!("scanning {filename}"));
            cmd = format!("nuclei -l {filename} -tags lfi -c 100");
        }
        "t" | "target" => {
            let mut target = String::new();
            std::io::stdin().read_line(&mut target).unwrap();
            info!(format!("scanning {target}"));
            cmd = format!("nuclei -u {target} -tags lfi -c 100");
        }
        _ => {
            err!("invalid input\nuse: t,target or f,file ");
        }
    };

    match run_cmd_string(cmd.clone()) {
        Some(xmd) => match xmd.stdout {
            Some(data) => {
                write_info_and_print!("{}", data);
            }
            None => match xmd.stderr {
                Some(data) => {
                    warn!("{}", data);
                    return None;
                }
                None => {
                    warn!("Nuclei: no output");
                    return None;
                }
            },
        },
        None => {
            warn!("running nuclei failed");
            return None;
        }
    };

    Some(())
}

pub async fn google(domain: String) -> Option<()> {
    println!("{}", "searching...".yellow());
    let search = google_search::v2::google_user_agent::search(domain, 50).await;
    match search {
        Ok(data) => {
            for i in &data {
                write_info_and_print!(
                    "{}",
                    format!(
                        " |- url: {}\n |- header: {}\n |- header info: {}\n |- desc: {}\n *",
                        i.url, i.title, i.title_info, i.description
                    )
                );
            }
        }
        Err(_) => {
            warn!("fetching google data failed");
        }
    }
    Some(())
}
pub mod cidr_notation {
    use {
        crate::save_util,
        cidr::Ipv4Cidr,
        colored::Colorize,
        rayon::prelude::*,
        std::{
            fmt::format,
            net::{SocketAddr, TcpStream},
            str::FromStr,
            time::Duration,
            u16,
        },
    };

    pub fn scan_all_ports(ip: String, Ports: Option<Vec<u16>>) -> Vec<u16> {
        info!(format!("Scanning {ip}"));
        let mut ports: Vec<u16> = Vec::new();
        if let Some(P) = Ports {
            ports = P;
        } else {
            info!("Scanning all Ports");
            ports = (1..=65535).collect();
        }
        ports
            .par_iter()
            .filter_map(|&port| {
                let address = format!("{}:{}", ip, port);
                let socket_addr: SocketAddr = address.parse().ok()?;
                match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(1)) {
                    Ok(_) => {
                        println!(" |-[{port}] OPEN");
                        Some(port)
                    }
                    Err(_) => None,
                }
            })
            .collect::<Vec<u16>>()
    }

    pub fn cidr_notation(ip: String, Ports: Option<Vec<u16>>) {
        let network = Ipv4Cidr::from_str(ip.as_str()).unwrap();
        let ips: Vec<_> = network.iter().map(|ip| ip.to_string()).collect::<Vec<_>>();

        let open_ports: Vec<(String, Vec<u16>)> = ips
            .into_par_iter()
            .filter_map(|ip| {
                let _open_ports = scan_all_ports(ip.clone(), Ports.clone());
                Some((ip.clone(), _open_ports))
            })
            .filter(|_open_ports| !_open_ports.1.is_empty())
            .collect();

        if open_ports.is_empty() {
            warn!("No open ports found");
        } else {
            for found in &open_ports {
                write_info!("{}", found.0);
                for __port in &found.1 {
                    write_info!(" |-{}", __port);
                }
            }
            write_info_and_print!(" *");
        }
    }
}

pub fn print_all_ips(ip: &str) -> Option<()> {
    let network = Ipv4Cidr::from_str(ip).unwrap();
    let ips: Vec<_> = network.iter().map(|ip| ip.to_string()).collect::<Vec<_>>();
    write_info_and_print!("{} Extracted IPs", ip);
    if ips.is_empty() {
        write_info_and_print!(" |- could not get any ip");
        write_info_and_print!(" *");
    } else {
        for _ip in &ips {
            write_info_and_print!(" |-{}", _ip);
            write_info_and_print!(" *");
        }
    }
    Some(())
}

pub mod xss_scan {
    use crate::{file_util, handle_deps, request, save_util, spyhunt_util};
    use colored::Colorize;
    use core::fmt;
    use futures::StreamExt;
    use std::{collections::VecDeque, fmt::write, usize};

    use {
        htmlescape::encode_minimal,
        rand::{self, distributions::Alphanumeric, Rng},
        rayon::iter::{IntoParallelRefIterator, ParallelIterator},
        reqwest::{self, Client},
        std::{collections::HashMap, env::vars, fmt::format},
        tokio::{self},
        urlencoding::{self},
    };

    #[derive(Debug, Clone, Copy)]
    pub enum Likelihood {
        Low,
        High,
    }
    use reqwest::header::RETRY_AFTER;
    use Likelihood::{High, Low};

    #[derive(Debug, Clone)]
    pub struct Vuln {
        pub url: String,
        pub parameter: String,
        pub payload: String,
        pub test_url: String,
        execution_likelihood: Likelihood,
    }

    impl fmt::Display for Likelihood {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let likelihood_str = match self {
                Likelihood::High => "High",
                Likelihood::Low => "Low",
            };
            write!(f, "{}", likelihood_str)
        }
    }

    impl Vuln {
        pub fn new() -> Self {
            Self {
                url: String::new(),
                parameter: String::new(),
                payload: String::new(),
                test_url: String::new(),
                execution_likelihood: Low,
            }
        }
    }

    impl fmt::Display for Vuln {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
             "  +URL: {}\n  +Parameter: {}\n  +Payload: {}\n  +Test URL: {}\n  +Execution Likelihood: {}\n",
                self.url, self.parameter, self.payload, self.test_url, self.execution_likelihood
            )
        }
    }

    /// Will scan for xxs using param injection
    /// on `domain`
    /// returns a Vec of successful injections `struct Vuln`
    /// which is checked by looking into the response text
    pub async fn xss_scan_url(domain: String, payloads: Vec<String>) -> Vec<Vuln> {
        println!("Scanning {domain}...");
        let calls = 1;

        let Session = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(std::time::Duration::new(5, 0))
            .build()
            .unwrap_or_else(|err| {
                eprintln!("unable to create Client Session\n{}", err);
                panic!();
            });

        //handle domain fix here
        let mut url =
            reqwest::Url::parse(request::urljoin(domain.clone(), "".to_string()).as_str()).unwrap();
        let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
        let mut vulnerabilities: Vec<Vuln> = vec![];

        for (param, val) in params.iter() {
            for payload in &payloads {
                let mut _vuln = Vuln::new();
                let random_string = generate_random_string(8);
                let test_payload = payload.replace("XSS", &random_string);
                let encoded_payload = encode_pay_load(test_payload.clone());

                // *val = encoded_payload;

                //fix req
                url.set_query(Some(
                    &params
                        .iter()
                        .map(|(key, value)| {
                            if value == val {
                                format!("{}={}", key, encoded_payload)
                            } else {
                                format!("{}={}", key, value)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("&")
                        .as_str(),
                ));

                // make req
                let res = Session.get(url.clone()).send().await;
                match res {
                    Ok(resp) => {
                        let mut _vuln: Vuln = Vuln::new();
                        match resp.text().await {
                            Ok(text) => {
                                if text.to_lowercase().contains(&random_string.to_lowercase()) {
                                    _vuln = Vuln {
                                        payload: encoded_payload.clone(),
                                        parameter: param.clone(),
                                        test_url: url.to_string().clone(),
                                        url: domain.clone(),
                                        execution_likelihood: Low,
                                    };
                                    println!(" |-{domain} : text found in response");
                                }

                                let pattern_script = regex::Regex::new(&format!(
                                    r#"<script>.*?alert\(['"]{}['"]\).*?</script>"#,
                                    regex::escape(&random_string)
                                ))
                                .unwrap();
                                let pattern_event = regex::Regex::new(&format!(
                                    r#"on\w+\s*=.*?alert\(['"]{}['"]\)"#,
                                    regex::escape(&random_string)
                                ))
                                .unwrap();

                                if pattern_script.is_match(&text) || pattern_event.is_match(&text) {
                                    println!(" |-{domain} : Probable vulnerability found");
                                    _vuln.execution_likelihood = High;
                                }
                                vulnerabilities.push(_vuln);
                            }
                            Err(_) => {
                                warn!("failed to get data");
                            }
                        };
                    }
                    Err(err) => {
                        if err.is_timeout() {
                            warn!(format!("fetching {} timedout.", domain));
                        }
                    }
                }; // end of req
            } // for
        } // for
        vulnerabilities
    }

    // /// This is so rayon can handle async
    // pub fn xss_scan_url_async_wrapper(domain: String, payloads: Vec<String>) -> Vec<Vuln> {
    //     let _runtime = tokio::runtime::Runtime::new().unwrap();
    //     _runtime.block_on(xss_scan_url(domain, payloads))
    // }

    pub async fn xss_scan_url_tokio(
        domains: Vec<String>,
        payloads: Vec<String>,
    ) -> Vec<(String, Vec<Vuln>)> {
        let mut domain_stream = tokio_stream::iter(domains.clone());
        let res = domain_stream
            .map(|domain| {
                let _payload = payloads.clone();
                let _domain = domain.clone();
                async move {
                    let data = xss_scan_url(_domain.clone(), _payload).await;
                    (_domain.clone(), data)
                }
            })
            .buffer_unordered(10)
            .collect::<Vec<(String, Vec<Vuln>)>>()
            .await;
        // = futures::future::join_all(handles)
        //     .await
        //     .into_iter()
        //     .filter_map(|res| res.ok())
        //     .collect();
        res
    }

    /// this takes in a  Vec of target because its multithreaded
    pub async fn xxs_scanner(targets: Vec<String>) -> Option<()> {
        // read file
        let deps_path = handle_deps::check_or_clone_spyhuntrs_deps();
        let payloads: Vec<String> = file_util::read_from_file(format!(
            "{deps_path}/payloads/xss.txt"
        ))
        .unwrap_or_else(|_| {
            warn!("Could not read from file payloads/xss.txt,exiting");
            [].to_vec()
        });
        if payloads.len() == 0 {
            return None;
        }

        info!("This might take a while please wait...");
        let mut __Vulns: Vec<(String, Vec<Vuln>)> =
            xss_scan_url_tokio(targets.clone(), payloads.clone()).await;

        if __Vulns.is_empty() {
            warn!("Could not find any payload injection");
            return Some(());
        }

        for ___vuln in &__Vulns {
            write_info_and_print!(" |- {}", ___vuln.0);
            if ___vuln.1.is_empty() {
                write_info_and_print!("  |- no vulns found");
                write_info_and_print!("  *");
            } else {
                for ____vulns in &___vuln.1 {
                    write_info_and_print!("  |- {}", ____vulns);
                    write_info_and_print!("  *");
                }
            }
        }
        Some(())
    }

    pub fn modify_url_test(url: &str) {
        let mut url = reqwest::Url::parse(url).expect("Invalid URL");

        let mut params: HashMap<String, String> = url.query_pairs().into_owned().collect();

        for (key, value) in params.iter_mut() {
            if value == "foo" {
                *value = "not_foo".to_string();
            }
        }

        url.set_query(Some(
            &params
                .iter()
                .map(|(key, value)| format!("{}={}", key, value))
                .collect::<Vec<_>>()
                .join("&"),
        ));

        println!("Modified URL: {}", url);
    }

    /// Generate a random String of `length`
    pub fn generate_random_string(length: usize) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }
    #[derive(Clone, Debug)]
    #[repr(usize)]
    pub enum Encode_pay_load_type {
        no_encoding = 0,
        url_encoding = 1,
        html_encoding = 2,
        full_url_encoding = 3,
        hex_encoding = 4,
        unicode_encoding = 5,
    }

    /// Encode a `payload` in a random encoding
    /// # Encodings
    /// - url encoding
    /// - html encoding
    /// - hex encoding
    /// - unicode
    /// - no encoding
    pub fn encode_pay_load(payload: String) -> String {
        return encode_pay_load_type(payload, None);
    }

    /// Encode a `payload` in a specific encoding
    /// # Encodings
    /// The enum `Encode_pay_load_type` holds the types
    /// - url encoding
    /// - html encoding
    /// - hex encoding
    /// - unicode
    /// - no encoding
    pub fn encode_pay_load_type(
        payload: String,
        encoding_type: Option<Encode_pay_load_type>,
    ) -> String {
        let encodings: Vec<fn(String) -> String> = vec![
            |s: String| {
                return s; // no encoding
            },
            |s: String| {
                return urlencoding::encode(s.as_str()).into_owned(); // url
            },
            |s: String| return htmlescape::encode_minimal(s.as_str()).to_string(), // html
            |s: String| {
                s.chars()
                    .map(|_char| return format!("%{:02x}", _char as u32))
                    .collect() // url encode
            },
            |s: String| {
                s.chars()
                    .map(|_char| return format!("&#x{:x}", _char as u32)) //hex
                    .collect()
            },
            |s: String| {
                s.chars()
                    .map(|_char| return format!("\\u{:04x}", _char as u32)) // unicode
                    .collect()
            },
        ];
        match encoding_type {
            Some(enc) => encodings[enc as usize](payload),
            None => {
                let random_number = rand::thread_rng().gen_range(0..encodings.len());
                encodings[random_number](payload)
            }
        }
    }
}

pub mod sqli_scan {

    use {
        crate::{
            check_if_save, file_util::read_from_file, handle_deps, request, save_util,
            spyhunt_util::xss_scan, user_agents::get_user_agent_prexisting,
        },
        colored::Colorize,
        rand::Rng,
        rayon::iter::{IntoParallelRefIterator, ParallelIterator},
        reqwest,
        std::{collections::HashMap, fmt},
    };

    #[derive(Debug, Clone)]
    pub struct Vuln {
        pub url: String,
        pub parameter: String,
        pub payload: String,
        pub test_url: String,
    }

    impl Vuln {
        pub fn new() -> Self {
            Self {
                url: String::new(),
                parameter: String::new(),
                payload: String::new(),
                test_url: String::new(),
            }
        }
    }

    impl fmt::Display for Vuln {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "  +URL: {}\n  +Parameter: {}\n  +Payload: {}\n  +Test URL: {}\n",
                self.url, self.parameter, self.payload, self.test_url,
            )
        }
    }

    pub fn encode_payload(payload: String) -> String {
        let __encode_pay_load_type = [
            xss_scan::Encode_pay_load_type::no_encoding,
            xss_scan::Encode_pay_load_type::url_encoding,
            xss_scan::Encode_pay_load_type::full_url_encoding,
        ];

        let random_num = rand::thread_rng().gen_range(0..__encode_pay_load_type.len());
        return xss_scan::encode_pay_load_type(
            payload,
            Some(__encode_pay_load_type[random_num].clone()),
        );
    }

    /// Will scan for sqli using param injection
    /// on `target`
    /// returns a Vec of successful injections `struct sqli_scan::Vuln`
    /// which is checked by looking into the response text  for errors
    pub async fn sqli_scan_url(target: String, error_payloads: Vec<String>) -> Vec<Vuln> {
        let sql_errors = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"Driver.*SQL SERVER",
            r"OLE DB.*SQL SERVER",
            r"SQL Server.*Driver",
            r"Warning.*mssql_.*",
            r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_.*",
            r"Warning.*\Wora_.*",
        ];

        let session = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(std::time::Duration::new(5, 0))
            .build()
            .unwrap_or_else(|err| {
                warn!(format!("unable to create Client Session\n{}", err));
                panic!();
            });

        //handle domain fix here
        let mut url =
            reqwest::Url::parse(request::urljoin(target.clone(), "".to_string()).as_str()).unwrap();
        let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
        let mut vulnerabilities: Vec<Vuln> = vec![];

        for (param, val) in params.iter() {
            for payload in &error_payloads {
                let encoded_payload = encode_payload(payload.to_string());

                //fix req
                url.set_query(Some(
                    &params
                        .iter()
                        .map(|(key, value)| {
                            if value == val {
                                format!("{}={}", key, encoded_payload)
                            } else {
                                format!("{}={}", key, value)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("&")
                        .as_str(),
                ));
                let res = session
                    .get(url.clone())
                    .header(
                        reqwest::header::USER_AGENT,
                        get_user_agent_prexisting()
                            .parse::<reqwest::header::HeaderValue>()
                            .unwrap(),
                    )
                    .send()
                    .await;
                match res {
                    Ok(resp) => {
                        match resp.text().await {
                            Ok(text) => {
                                for error in sql_errors {
                                    let regex =
                                        regex::Regex::new(error).expect("Invalid regex pattern");
                                    if regex.is_match(&text) {
                                        println!(
                                            " |-{target} :Found SQL error matching pattern: {}",
                                            text
                                        );
                                        vulnerabilities.push(Vuln {
                                            payload: encoded_payload.clone(),
                                            parameter: param.clone(),
                                            test_url: url.to_string().clone(),
                                            url: target.clone(),
                                        });

                                        break; // Stop after finding the first match
                                    }
                                }
                            }
                            Err(_) => {
                                warn!("failed to get data");
                            }
                        };
                    }
                    Err(err) => {
                        if err.is_timeout() {
                            warn!(format!("fetching {} timedout.", target));
                        }
                    }
                }; // end of req
            }
        }
        vulnerabilities
    }

    /// function for rayon to handle multithreading
    pub fn sqli_scan_url_async_wrapper(domain: String, payloads: Vec<String>) -> Vec<Vuln> {
        let _runtime = tokio::runtime::Runtime::new().unwrap();
        _runtime.block_on(sqli_scan_url(domain, payloads))
    }

    /// this takes in a Vec targets
    /// because of multithreading
    /// will run the `sqli_scan::sqli_scan_url(...)`
    /// on each target.
    pub fn sqli_scanner(target: Vec<String>) -> Option<()> {
        // he opens payloads file but does nothing to it
        // whyyyyyyyyyyy the hell????
        // open payloads/sqli.txt
        let deps_path = handle_deps::check_or_clone_spyhuntrs_deps();
        let mut payloads: Vec<String> =
            read_from_file(format!("{deps_path}/payloads/sqli.txt")).unwrap_or([].to_vec());

        if payloads.is_empty() {
            payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' UNION SELECT NULL, NULL, NULL --",
                "1' ORDER BY 1--+",
                "1' ORDER BY 2--+",
                "1' ORDER BY 3--+",
                "1 UNION SELECT NULL, NULL, NULL --",
            ]
            .to_vec()
            .iter()
            .map(|&s| s.to_string())
            .collect();
        }

        let _vulnerabilities: Vec<(String, Vec<Vuln>)> = target
            .par_iter()
            .filter_map(|_target| {
                let _vulns = sqli_scan_url_async_wrapper(_target.clone(), payloads.clone());
                Some((_target.clone(), _vulns))
            })
            .collect::<Vec<(String, Vec<Vuln>)>>();

        if _vulnerabilities.is_empty() {
            write_info_and_print!(" |- Could not find any payload injection");
            return Some(());
        } else {
            for ___vuln in &_vulnerabilities {
                write_info_and_print!(" |- {}", ___vuln.0);
                if ___vuln.1.is_empty() {
                    write_info_and_print!("  |- no vulns found");
                    write_info_and_print!("  *");
                } else {
                    for ____vulns in &___vuln.1 {
                        write_info_and_print!("  |- {}", ____vulns);
                        write_info_and_print!("  *");
                    }
                }
            }
        }
        Some(())
    }
}

mod webserver_scan {
    use colored::Colorize;
    use std::time::Duration;
    use std::{collections::HashMap, u16};

    use reqwest::{self, header::HeaderMap};

    pub async fn get_server_info(url: String, path: String) -> Option<(HeaderMap, u16, String)> {
        let session = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::new(10, 0))
            .build()
            .unwrap_or_else(|err| {
                warn!(format!("unable to create client session\n{}", err));
                panic!();
            });

        // reqwest::urljoin(...)
        let resp = session.get(url.clone()).send().await;
        match resp {
            Ok(res) => {
                let status_code = res.status().as_u16();
                let headers = res.headers().clone();
                let text = match res.text().await {
                    Ok(text_data) => text_data,
                    Err(_) => "".to_string(),
                };

                return Some((headers, status_code, text));
            }
            Err(err) => {
                if err.is_timeout() {
                    warn!(format!("{url} timed out"));
                }
                return None;
            }
        }
    }

    pub fn analyze_headers(headers: HeaderMap) -> HashMap<String, String> {
        let mut server_info: HashMap<String, String> = HashMap::new();

        for (header, value) in &headers {
            if header.to_string().to_lowercase() == "server" {
                server_info.insert(
                    "Server".to_string(),
                    value.to_str().unwrap_or("").to_string(),
                );
            } else if header.to_string().to_lowercase() == "x-powered-by" {
                server_info.insert(
                    "X-Powered-By".to_string(),
                    value.to_str().unwrap_or("").to_string(),
                );
            } else if header.to_string().to_lowercase() == "x-aspnet-version" {
                server_info.insert(
                    "ASP.NET".to_string(),
                    value.to_str().unwrap_or("").to_string(),
                );
            } else if header.to_string().to_lowercase() == "x-generator" {
                server_info.insert(
                    "Generator".to_string(),
                    value.to_str().unwrap_or("").to_string(),
                );
            }
        }
        return server_info;
    }

    pub async fn check_specific_files(url: String) -> HashMap<String, String> {
        let mut files_to_check: HashMap<&str, HashMap<&str, &str>> = HashMap::new();

        files_to_check.insert(
            "/favicon.ico",
            HashMap::from([("Apache", "Apache"), ("Nginx", "Nginx")]),
        );

        files_to_check.insert(
            "/server-status",
            HashMap::from([("Apache", "Apache Status")]),
        );
        files_to_check.insert("/nginx_status", HashMap::from([("Nginx", "Nginx Status")]));
        files_to_check.insert("/web.config", HashMap::from([("IIS", "IIS Config")]));
        files_to_check.insert("/phpinfo.php", HashMap::from([("PHP", "PHP Version")]));

        let mut results: HashMap<String, String> = HashMap::new();

        for (file, signatures) in &files_to_check {
            let (_headers, status, content) = get_server_info(url.clone(), file.to_string())
                .await
                .unwrap();

            if status == 200 {
                for (server, signature) in signatures {
                    if content.contains(signature) {
                        results.insert(server.to_string(), format!("Detected via {file}"));
                    }
                }
            }
        }
        return results;
    }

    /// entry point in webserver_scan
    pub async fn detect_web_server(url: String) -> Option<()> {
        //url fix
        println!("Scanning {url}");
        let mut success: bool = true;
        let (headers, status, _content) = get_server_info(url.clone(), "".to_string())
            .await
            .unwrap_or_else(|| {
                success = false;
                (HeaderMap::new(), u16::max_value(), "".to_string())
            });

        if !success && status == u16::max_value() {
            warn!("Error Unable to connect to server");
            return None;
        }

        let server_info: HashMap<String, String> = analyze_headers(headers.clone());
        let mut return_info: HashMap<String, String> = HashMap::new();

        if !server_info.contains_key("Server") {
            if headers.contains_key(reqwest::header::SET_COOKIE) {
                match headers.get(reqwest::header::SET_COOKIE) {
                    Some(some) => {
                        if some.to_str().unwrap_or("").contains("ASPSESSIONID") {
                            return_info.insert("Likely".to_string(), "IIS".to_string());
                        } else if some.to_str().unwrap_or("").contains("PHPSESSID") {
                            return_info.insert("Likely".to_string(), "PHP".to_string());
                        }
                    }
                    None => {}
                }
            }
        }

        check_specific_files(url).await.into_iter().for_each(|map| {
            return_info.insert(map.0, map.1);
        });

        if !return_info.is_empty() {
            for (key, value) in return_info {
                println!("{key}:{value}");
            }
        } else {
            warn!("Unable to determine web server");
        }

        if headers.contains_key("CF-RAY") {
            println!("Cloudflare detected");
        }
        if headers.contains_key("X-Varnish") {
            println!("Varnish Cache detected");
        }

        Some(())
    }
}

pub mod javascript_scan {
    use {
        colored::Colorize,
        rayon::iter::{IntoParallelRefIterator, ParallelIterator},
        scraper::{Html, Selector},
        std::collections::HashMap,
    };

    pub fn is_valid_url(url: String) -> bool {
        match reqwest::Url::parse(url.as_str()) {
            Ok(_) => true,
            _ => false,
        }
    }

    pub async fn get_js_file(url: String) -> Vec<String> {
        let session = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(std::time::Duration::new(5, 0))
            .build()
            .unwrap_or_else(|_err| {
                warn!(format!("unable to create Client Session\n{}", _err));
                panic!();
            });

        let response = session.get(url.clone()).send().await;
        let mut js_files = Vec::new();
        match response {
            Ok(resp) => {
                match resp.text().await {
                    Ok(body) => {
                        let document = Html::parse_document(&body);
                        let script_selector = Selector::parse("script").unwrap();
                        let link_selector = Selector::parse("link[rel='stylesheet']").unwrap();

                        // Find all <script> tags with src attributes
                        for element in document.select(&script_selector) {
                            if let Some(src) = element.value().attr("src") {
                                if let Ok(script_url) = reqwest::Url::parse(url.clone().as_str())
                                    .and_then(|base| base.join(src))
                                {
                                    js_files.push(script_url.to_string());
                                }
                            }
                        }

                        // Regex for extracting JavaScript URLs
                        let js_in_css_re =
                            regex::Regex::new(r#"url\([\'\"]?(.*?\.js)[\'\"]?\)"#).unwrap();
                        let js_in_script_re =
                            regex::Regex::new(r#"[\'\"]([^\'\"]*\.js)[\'\"]"#).unwrap();

                        // Find JavaScript files in <link> tags
                        for link in document.select(&link_selector) {
                            if let Some(href) = link.value().attr("href") {
                                let css_url = reqwest::Url::parse(url.clone().as_str())
                                    .unwrap()
                                    .join(href)
                                    .unwrap();
                                if is_valid_url(css_url.to_string()) {
                                    let css_response =
                                        session.get(css_url.as_str()).send().await.unwrap();
                                    let css_text = css_response.text().await.unwrap();
                                    for js_match in js_in_css_re.captures_iter(&css_text) {
                                        if let Some(js_path) = js_match.get(1) {
                                            let js_url = css_url.join(js_path.as_str()).unwrap();
                                            if is_valid_url(js_url.to_string()) {
                                                js_files.push(js_url.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Find JavaScript files mentioned in inline <script> tags
                        for script in document.select(&script_selector) {
                            if let Some(script_content) = script.text().next() {
                                for js_match in js_in_script_re.captures_iter(script_content) {
                                    if let Some(js_path) = js_match.get(1) {
                                        let js_url = reqwest::Url::parse(url.as_str())
                                            .unwrap()
                                            .join(js_path.as_str())
                                            .unwrap();
                                        if is_valid_url(js_url.to_string()) {
                                            js_files.push(js_url.to_string());
                                        }
                                    }
                                }
                            }
                        }

                        // Print the collected JavaScript file URLs
                        for js_file in &js_files {
                            println!("{}", js_file);
                        }
                    }
                    _ => {}
                }
            }

            Err(err) => {
                if err.is_timeout() {
                    warn!(format!("ERR: {url} Timedout"));
                }
            }
        }
        return js_files;
    }

    pub async fn analyze_js_file(js_url: String) -> (String, usize, HashMap<String, String>) {
        use regex::Regex as r;
        let interesting_patterns = HashMap::from([
            (
                "API Keys",
                r::new(r#"(?i)(?:api[_-]?key|apikey)["\s:=]+(["\'][a-zA-Z0-9_\-]{20,}["\'])"#).unwrap(),
            ),
            (
                "Passwords",
                r::new(r#"(?i)(?:password|passwd|pwd)["\s:=]+(["\'][^"\']{8,}["\'])"#).unwrap(),
            ),
            (
                "Tokens",
                r::new(
                    r#"(?i)(?:token|access_token|auth_token)["\s:=]+(["\'][a-zA-Z0-9_\-]{20,}["\'])"#,
                ).unwrap(),
            ),
            (
                "Sensitive Functions",
                r::new(r#"(?i)(eval|setTimeout|setInterval)\s*\([^)]+\)"#).unwrap(),
            ),
        ]);
        let mut content_len = 0;
        let mut findings: HashMap<String, String> = HashMap::new();
        let session = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(std::time::Duration::new(5, 0))
            .build()
            .unwrap_or_else(|_err| {
                warn!(format!("unable to create Client Session\n{}", _err));
                panic!();
            });
        match session.get(js_url.clone()).send().await {
            Ok(resp) => match resp.text().await {
                Ok(text) => {
                    content_len = text.len();
                    for (name, pattern) in interesting_patterns {
                        for re_match in pattern.find_iter(text.clone().as_str()) {
                            println!("Found match {name} {}", re_match.as_str());
                            findings.insert(name.to_string(), re_match.as_str().to_string());
                        }
                    }
                }
                Err(_) => {}
            },
            Err(err) => {
                if err.is_timeout() {
                    warn!(format!("Err: {js_url} timedout."));
                }
            }
        }
        return (js_url, content_len, findings);
    }

    pub fn analyze_js_files_async_wrapper(url: String) -> (String, usize, HashMap<String, String>) {
        let _runtime = tokio::runtime::Runtime::new().unwrap();
        return _runtime.block_on(analyze_js_file(url));
    }

    pub async fn javascript_scan(url: String) {
        let js_files = get_js_file(url).await;
        if js_files.is_empty() {
            return;
        }

        let analyzed_files: Vec<(String, usize, HashMap<String, String>)> = js_files
            .par_iter()
            .filter_map(|_file| {
                let x = analyze_js_files_async_wrapper(_file.to_string());
                Some(x)
            })
            .collect::<Vec<(String, usize, HashMap<String, String>)>>();

        for file in &analyzed_files {
            println!(
                "FILE: {}\n CONTENT LEN: {}\n FINDINGS: {:#?}\n",
                file.0, file.1, file.2
            );
        }
    }
}

/// i can't...
/// i mean , it has one more unique regex pattern it looks for , but?
/// you couldn't have added this to the other 2 javascript searching functions?????????
pub mod javascript_endpoints {
    use crate::{request, save_util};
    use colored::Colorize;
    use rayon::prelude::*;

    pub fn find_endpoints(js_content: String) -> Vec<String> {
        let endpoint_pattern =
            regex::Regex::new(r#"(?:"|\'|\`)(/(?:api/)?[\w-]+(?:/[\w-]+)*(?:\.\w+)?)"#).unwrap();

        let matches: Vec<_> = endpoint_pattern
            .find_iter(js_content.as_str())
            .map(|m| m.as_str().to_string())
            .collect();

        matches
    }

    pub async fn analyze_js_files(url: String) -> (String, Vec<String>) {
        println!(" - analyzing {url}");
        let response = match fetch_url!(url.clone()) {
            Ok(resp) => match resp.text().await {
                Ok(text) => text,
                Err(err) => {
                    warn!(format!("Err : {err}"));
                    return (String::new(), vec![String::new()]);
                }
            },
            Err(err) => {
                warn!(format!("Err : {err}"));
                return (String::new(), vec![String::new()]);
            }
        };

        let endpoints = find_endpoints(response);

        (url, endpoints)
    }

    pub fn analyze_js_files_wrapper(js_url: String) -> (String, Vec<String>) {
        let _runtime = tokio::runtime::Runtime::new().unwrap();
        _runtime.block_on(analyze_js_files(js_url))
    }

    pub async fn process_js_files(js_urls: Vec<String>) {
        let js_files: Vec<String> = Vec::new();
        let results: Vec<(String, Vec<String>)> = js_urls
            .par_iter()
            .filter_map(|url| {
                let data = analyze_js_files_wrapper(url.clone());
                Some(data)
            })
            .collect();

        if results.is_empty() {
            warn!(format!("no results found"));
            return;
        }

        for (url, vec) in results {
            write_info_and_print!("{}", url);
            if vec.is_empty() {
                write_info_and_print!(" |- No results found\n *");
            } else {
                for i in vec {
                    write_info_and_print!(" |-{}", i);
                }
                write_info_and_print!(" *");
            }
        }
    }
}

pub mod param_miner {
    use std::collections::HashMap;

    use super::xss_scan;
    use crate::{
        file_util::{file_exists, read_from_file},
        request::{self, urljoin},
        save_util,
    };
    use colored::Colorize;
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
    use reqwest::{header::HeaderMap, Response};

    pub fn detect_reflection(response: String, headers: HeaderMap, payload: String) -> bool {
        if response.contains(&payload) {
            return true;
        }

        if headers.contains_key(payload.clone()) {
            return true;
        }
        let mut return_value = false;
        headers.values().for_each(|val| {
            match val.to_str() {
                Ok(ok) => {
                    if ok == payload.as_str() {
                        return_value = true;
                    }
                }
                _ => {}
            };
        });
        return_value
    }

    pub fn analyze_response_difference(
        orginal_response_text: String,
        modified_response: String,
    ) -> bool {
        if orginal_response_text.len() != modified_response.len() {
            return true;
        }
        return false;
    }

    pub enum param_miner_result {
        reflected,
        potential,
        status_changed,
        nil,
    }
    pub async fn brute_force_parameter(
        url: String,
        param: String,
        orginal_response_text: String,
    ) -> (String, param_miner_result) {
        let payload: String = xss_scan::generate_random_string(10);
        let mut fullurl = validate_url!(url.clone());

        if url.contains("?") {
            fullurl += "&";
        } else {
            fullurl += "?";
        }

        let test_url = format!("{fullurl}{param}={payload}");

        let session = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(std::time::Duration::new(5, 0))
            .build()
            .unwrap_or_else(|err| {
                warn!(format!("unable to create Client Session\n{}", err));
                panic!();
            });
        let mut headers: HeaderMap = HeaderMap::new();
        let text = match session.get(test_url.clone()).send().await {
            Ok(resp) => {
                headers = resp.headers().clone();
                match resp.text().await {
                    Ok(data) => data,
                    Err(_) => "".to_string(),
                }
            }
            Err(err) => {
                if err.is_timeout() {
                    warn!(format!("Err {test_url} Connection timedout"));
                }
                "".to_string()
            }
        };

        if text.is_empty() {
            warn!("No data retrieved");
            return ("".to_string(), param_miner_result::nil);
        }

        if detect_reflection(text.clone(), headers, payload.clone()) {
            info!("Reflected parametet Found");
            return (param, param_miner_result::reflected);
        };

        if analyze_response_difference(text, orginal_response_text) {
            info!(" Potential parameter found (response changed)");
            return (param, param_miner_result::potential);
        }

        return ("".to_string(), param_miner_result::nil);
    }

    pub async fn scan_common_parameters(url: String) -> Vec<String> {
        info!(format!("Performing common parameter scan on {url}"));
        let common_params: Vec<&str> = vec![
            "id", "page", "search", "q", "query", "file", "filename", "path", "dir",
        ];

        let orginal_text = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(std::time::Duration::new(5, 0))
            .build()
            .unwrap_or_else(|err| {
                warn!(format!("unable to create Client Session\n{}", err));
                panic!();
            })
            .get(url.clone())
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        let mut found_params: Vec<String> = Vec::new();

        for param in common_params {
            let (result, _) =
                brute_force_parameter(url.clone(), param.to_string().clone(), orginal_text.clone())
                    .await;

            if !result.len() == 0 {
                println!(" |-param: {}", result.clone());
                found_params.push(result.clone());
            }
        }

        return found_params;
    }

    pub async fn extract_parameters_from_html(url: String) -> Vec<String> {
        info!(format!(
            "Performing parameter extraction from html on {url}"
        ));
        let orginal_text = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(std::time::Duration::new(5, 0))
            .build()
            .unwrap_or_else(|err| {
                warn!(format!("unable to create Client Session\n{}", err));
                panic!();
            })
            .get(url.clone())
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let form_params = regex::Regex::new(r#"name=["\']([^"\']+)["\']"#).unwrap();
        let js_params =
            regex::Regex::new(r#"(?:get|post)\s*\(\s*["\'][^"\']*\?([^"\'&]+)="#).unwrap();

        let mut form_matches: Vec<_> = form_params
            .find_iter(orginal_text.as_str())
            .map(|text| text.as_str().to_string())
            .collect();

        let mut js_matches: Vec<_> = js_params
            .find_iter(orginal_text.as_str())
            .map(|text| text.as_str().to_string())
            .collect();

        form_matches.append(&mut js_matches);
        return form_matches;
    }

    pub fn brute_force_parameter_async_wrapper(
        url: String,
        param: String,
        orginal_response_text: String,
    ) -> (String, param_miner_result) {
        let _runtime = tokio::runtime::Runtime::new().unwrap();
        _runtime.block_on(brute_force_parameter(url, param, orginal_response_text))
    }

    pub async fn param_miner(url: String, wordlist: String) -> Option<()> {
        let orginal_text = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(std::time::Duration::new(5, 0))
            .build()
            .unwrap_or_else(|err| {
                warn!(format!("unable to create Client Session\n{}", err));
                panic!();
            })
            .get(url.clone())
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        let mut common_params = scan_common_parameters(url.clone()).await;
        let mut extracted_params = extract_parameters_from_html(url.clone()).await;

        if !file_exists(&wordlist) {
            warn!(format!("Wordlist file not found : {wordlist}"));
            return None;
        }
        let mut wordlists = read_from_file(wordlist.clone()).unwrap();

        let mut all_params = Vec::new();
        all_params.append(&mut common_params);
        all_params.append(&mut extracted_params);
        all_params.append(&mut wordlists);

        info!("Testing all parameters");
        let results = all_params
            .par_iter()
            .filter_map(|param| {
                Some(brute_force_parameter_async_wrapper(
                    url.clone(),
                    param.to_string(),
                    orginal_text.clone(),
                ))
            })
            .collect::<Vec<(String, param_miner_result)>>();

        let get_param_miner_str = |p: param_miner_result| -> &str {
            use param_miner_result::*;
            match p {
                reflected => "reflected",
                potential => "potential",
                status_changed => "status_changed",
                _ => "nil",
            }
        };
        for res in results {
            match res.1 {
                param_miner_result::nil => {}
                _ => {
                    write_info_and_print!(" |-{}: {}", res.0, get_param_miner_str(res.1));
                }
            };
        }
        Some(())
    }
}

/// not trusted
pub fn haveibeenpwned() {}

pub mod custom_headers {

    use crate::save_util::save_vec_strings;
    use crate::{file_util, request};
    use colored::Colorize;
    use regex::bytes::Match;
    use reqwest::redirect::Policy;
    use reqwest::{
        self,
        header::{HeaderMap, HeaderName, HeaderValue},
        Method, RequestBuilder,
    };
    use reqwest::{Proxy, Url};
    use scraper::{self, Selector};
    use std::fmt::{self, format};
    use std::hash::Hash;
    use std::io::{stdout, Write};
    use std::time::SystemTime;
    use std::{collections::HashMap, time::Instant};

    #[derive(Debug, Clone)]
    pub struct request_info {
        pub url: String,
        pub method: Option<String>,
        pub custom_heaaders: Option<HashMap<String, String>>,
        pub data: Option<String>, // shit is never used
        pub params: Option<(String, String)>,
        pub auth: Option<String>,
        pub proxies: Option<String>,
        pub allow_redirects: Option<bool>,
        pub verbose: Option<bool>,
    }
    impl request_info {
        pub fn new() -> Self {
            Self {
                url: String::new(),
                method: None,
                custom_heaaders: None,
                data: None,
                params: None,
                auth: None,
                proxies: None,
                allow_redirects: None,
                verbose: None,
            }
        }
    }
    impl fmt::Display for request_info {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let mut print_str: String = String::new();

            print_str += format!("[URL]:{}\n", self.url.clone()).as_str();

            if let Some(_method) = &self.method {
                print_str += format!("[METHOD]: {}\n", _method).as_str();
            }

            if let Some(_cheaders) = &self.custom_heaaders {
                let mut __headers: String = String::new();
                for (k, v) in _cheaders.iter() {
                    __headers += format!(" ({k}:{v}) ").as_str();
                }
                print_str += format!("[CUSTOM HEADERS]: {}\n", __headers).as_str();
            }

            if let Some(_params) = &self.params {
                print_str += format!("[PARAMS]: {}:{}\n", _params.0, _params.1).as_str();
            }

            if let Some(_auth) = &self.auth {
                print_str += format!("[AUTH]: {}\n", _auth).as_str();
            }

            if let Some(_proxy) = &self.proxies {
                print_str += format!("[PROXY]: {}\n", _proxy).as_str();
            }
            if let Some(_allow_redirect) = &self.allow_redirects {
                print_str += format!("[ALLOW REDIRECT]: {}\n", _allow_redirect).as_str();
            }

            write!(f, "{}", print_str)
        }
    }
    pub fn extract_links(content: String, url: String) {
        let document = scraper::Html::parse_document(&content);
        let mut newlinks: Vec<String> = Vec::new();
        let a_tags = scraper::Selector::parse("a[href]").unwrap();

        let base_url = reqwest::Url::parse(url.as_str()).unwrap();

        for element in document.select(&a_tags) {
            if let Some(href) = element.value().attr("href") {
                if let Ok(full_url) = base_url.join(href) {
                    newlinks.push(full_url.to_string());
                }
            }
        }
    }

    // url: String,
    // method: Option<String>,
    // custom_heaaders: Option<HashMap<String, String>>,
    // data: Option<String>, // shit is never used
    // params: Option<(String, String)>,
    // auth: Option<String>,
    // proxies: Option<String>,
    // allow_redirects: Option<bool>,
    // verbose: Option<bool>,
    pub async fn send_request(req: request_info) -> (u64, Option<reqwest::Response>, u16) {
        let mut builder = reqwest::Client::builder();
        let mut request: RequestBuilder;
        let mut url = req.url.clone();

        /* values to insert into request*/
        let mut Headers: HeaderMap = HeaderMap::new();

        if let Some(_allow_redirects) = req.allow_redirects {
            builder = builder.redirect(Policy::limited(10));
        }

        if let Some(_proxy) = req.proxies {
            builder = builder.proxy(Proxy::all(_proxy).unwrap());
        }

        /* modify Session */

        let mut session = builder.build().unwrap();

        if let Some(_method) = req.method {
            match _method.to_lowercase().as_str() {
                "put" => {
                    request = session.put(url);
                }
                "patch" => {
                    request = session.patch(url);
                }
                "post" => {
                    request = session.post(url);
                }
                "get" => {
                    request = session.get(url);
                }
                _ => {
                    request = session.get(url);
                }
            }
        } else {
            request = session.get(url);
        }

        if let Some(_auth) = req.auth {
            let _place = match _auth.find(":") {
                Some(place) => place,
                None => match _auth.find(" ") {
                    Some(place) => place,
                    None => {
                        warn!("Could not get password and username\nEnter in  \"username:password\" or \"username password\"");
                        0
                    }
                },
            };
            if _place != 0 {
                let (username, password) = _auth.split_at(_place);
                request = request.basic_auth(username, Some(password));
            }
        }

        if let Some(_params) = req.params {
            if !_params.0.is_empty() && !_params.1.is_empty() {
                request = request.query(&_params);
            } else {
                warn!("Could not parse Params, enter Header and value seperated by a whitespace\nEg: Connection Close");
            }
        }

        if let Some(_header) = req.custom_heaaders {
            for (k, v) in _header {
                Headers.insert(
                    k.parse::<HeaderName>().unwrap(),
                    v.parse::<HeaderValue>().unwrap(),
                );
            }
        }

        request = request.headers(Headers);
        let mut resp: Option<reqwest::Response> = None;
        let mut status: u16 = 0;
        let start = Instant::now();
        let mut finish = std::time::Duration::from_secs(0);
        match request.send().await {
            Ok(res) => {
                finish = start.elapsed();
                status = res.status().as_u16();
                resp = Some(res);
            }
            Err(err) => {
                if err.is_timeout() {
                    warn!("Request Timedout");
                }
                if err.is_request() {
                    warn!("Err from request");
                }
                if err.is_connect() {
                    warn!("Err from connection issue");
                }
            }
        }
        println!("Done");
        return (finish.as_secs(), resp, status);
    }

    pub async fn custom_headers(initial_url: String) -> () {
        // let mut url: String = String::new();
        // let mut method: Option<String> = None;
        // let mut custom_heaaders: Option<HashMap<String, String>> = None;
        // let mut data: Option<String> = None;
        // let mut params: Option<(String, String)> = None;
        // let mut auth: Option<String> = None;
        // let mut proxies: Option<String> = None;
        // let mut allow_redirects: Option<bool> = None;
        // let mut verbose: Option<bool> = None;

        let mut _request_info: request_info = request_info::new();
        let mut verbose: bool = false;
        let mut save_to_file: bool = false;
        let mut path: String = String::new();
        _request_info.url = initial_url.clone();
        loop {
            let mut input = String::new();
            println!("\nCurrent URL: {}", _request_info.url.clone());
            println!("\nOptions:");
            println!("1. Send The request");
            println!("2. Add custom header");
            println!("3. Change request method");
            println!("4. Change URL");
            println!("5. Load headers from file");
            println!("6. Set authentication");
            println!("7. Set proxy");
            println!("8. Toggle redirect following");
            println!("9. Save response to file");
            println!("10. Trip Verbose: Prints INFO before sending");
            println!("11. Exit");

            std::io::stdin().read_line(&mut input).unwrap();
            let num = input.replace('\n', "");
            match num.parse::<i32>() {
                Ok(int) => {
                    match int {
                        1 => {
                            if _request_info.url.len() == 0 {
                                println!("No url loaded");
                            } else {
                                if verbose {
                                    println!("Sending request\n{}", _request_info);
                                } else {
                                    println!("Sending request...");
                                }

                                let (time, resp, status) =
                                    send_request(_request_info.clone()).await;

                                println!("[time]: {}\n[status code]: {}", time, status);

                                let mut buffer: Vec<String> = Vec::new();
                                if save_to_file {
                                    save_to_file = false; // reset
                                    println!("Writing response to file...");
                                    if let Some(res) = resp {
                                        match res.text().await {
                                            Ok(text) => {
                                                let b = text.split('\n').collect::<Vec<&str>>();

                                                for i in b {
                                                    buffer.push(i.to_string());
                                                }
                                            }
                                            Err(..) => {
                                                warn!("Could not save data to file");
                                            }
                                        }
                                    }
                                    match file_util::write_to_file(buffer, path.clone()) {
                                        Ok(..) => {
                                            println!("Successful");
                                        }
                                        Err(..) => {
                                            println!("Failed");
                                        }
                                    }
                                };
                            }
                        }
                        2 => {
                            let mut n: String = String::new();
                            println!("Enter header as: <Header> <Value>");
                            std::io::stdin().read_line(&mut n).unwrap();

                            // incase of human error
                            n = n.replace(">", "").replace("<", "");

                            let x: Vec<_> = n.split(' ').collect();
                            if x.len() != 2 {
                                warn!("incorrect formating");
                            } else {
                                let mut map = HashMap::from([(x[0].to_string(), x[1].to_string())]);
                                if let Some(ref _map) = _request_info.custom_heaaders {
                                    for (k, v) in _map {
                                        map.insert(k.to_string(), v.to_string());
                                    }
                                }

                                _request_info.custom_heaaders = Some(map);
                                println!("Added Headers");
                            }
                        }
                        3 => {
                            let mut n: String = String::new();
                            println!("Available methods: GET POST PATCH PUT");
                            std::io::stdin().read_line(&mut n).unwrap();
                            _request_info.method = Some(n);
                            println!("Method set");
                        }
                        4 => {
                            let mut n: String = String::new();
                            println!("Enter new url");
                            std::io::stdin().read_line(&mut n).unwrap();
                            match reqwest::Url::parse(n.as_str()) {
                                Ok(..) => {
                                    _request_info.url = n.clone();
                                    println!("url: {} is set", n.clone());
                                }
                                Err(..) => {
                                    warn!("Url invalid, please add scheme if it doesn't have one eg https://www.example.com");
                                }
                            }
                        }
                        5 => {
                            let mut n: String = String::new();
                            println!("Enter Filename");
                            println!("Make sure Content in file is formatted into:");
                            println!("Header Value");
                            std::io::stdin().read_line(&mut n).unwrap();

                            if !file_util::file_exists(&n) {
                                warn!(format!("file {} does not exist", n.clone()));
                            } else {
                                let headers = file_util::read_from_file(n.clone());
                                match headers {
                                    Ok(h) => {
                                        let mut map: HashMap<String, String> = HashMap::new();
                                        // let mut map =
                                        //     HashMap::from([(x[0].to_string(), x[1].to_string())]);
                                        let mut had_errors_processing = false;

                                        for line in h {
                                            let x: Vec<_> = line.split(' ').collect();
                                            if x.len() == 2 {
                                                map.insert(x[0].to_string(), x[1].to_string());
                                            } else {
                                                had_errors_processing = true;
                                            }
                                        }

                                        if had_errors_processing {
                                            println!("Had errors when processing lines to headers");
                                        }

                                        if let Some(ref _map) = _request_info.custom_heaaders {
                                            for (k, v) in _map {
                                                map.insert(k.to_string(), v.to_string());
                                            }
                                        }
                                        _request_info.custom_heaaders = Some(map.clone());
                                    }
                                    Err(..) => {
                                        warn!(format!("Failed to read from file {n}"));
                                    }
                                }
                                println!("setting custom headers from file done");
                            }
                        }
                        6 => {
                            println!(
                                "Enter authentication: username:password or username password"
                            );
                            let mut n: String = String::new();
                            std::io::stdin().read_line(&mut n).unwrap();
                            _request_info.auth = Some(n);
                            println!("Setting auth Done");
                        }
                        7 => {
                            println!("Enter proxy link :");
                            let mut n: String = String::new();
                            std::io::stdin().read_line(&mut n).unwrap();
                            _request_info.proxies = Some(n);
                            println!("Setting Proxy Done");
                        }
                        8 => {
                            if let Some(state) = _request_info.allow_redirects {
                                _request_info.allow_redirects = Some(!state);
                            } else {
                                _request_info.allow_redirects = Some(true);
                            }
                            println!("Toggled redirect following");
                        }
                        9 => {
                            println!("9.Enter filename:");
                            let mut n: String = String::new();
                            std::io::stdin().read_line(&mut n).unwrap();
                            save_to_file = true;
                            path = n.clone();
                        }
                        10 => {
                            verbose = !verbose;
                            println!("Toggled verbose to : {verbose}");
                        }
                        11 => {
                            println!("Exiting...");
                            std::process::exit(0);
                        }
                        _ => {
                            println!("Invalid option,pick between 1-11");
                        }
                    };
                }
                Err(_) => {
                    println!("Enter a valid option");
                }
            }
        }
    }
}

pub mod open_redirect {
    use crate::request;
    use crate::save_util;
    use cidr::parsers;
    use colored::Colorize;
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
    use reqwest::Url;
    use tokio::runtime;

    pub async fn test_single_payload(
        url: String,
        payload: String,
        original_domain: String,
        test_domain: &str,
    ) -> (String, String) {
        info!(format!("Testing {url}"));
        let full_url = request::urljoin(url.clone(), payload);
        let Session = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(0))
            .timeout(std::time::Duration::new(5, 0))
            .build()
            .unwrap_or_else(|err| {
                warn!(format!("unable to create Client Session\n{}", err));
                panic!();
            });

        let resp = Session.get(full_url.clone()).send().await;
        match resp {
            Ok(res) => match res.status().as_u16() {
                301 | 302 | 303 | 307 | 308 => {
                    let location = res.headers().get(reqwest::header::LOCATION);
                    let mut __domain: String = String::new();

                    if let Some(_location) = location {
                        if Url::parse(_location.to_str().unwrap_or("")).is_ok() {
                            __domain = _location.to_str().unwrap().to_string();
                        } else if Url::parse(
                            format!("{full_url}{}", _location.to_str().unwrap_or("")).as_str(),
                        )
                        .is_ok()
                        {
                            __domain =
                                format!("{full_url}{}", _location.to_str().unwrap().to_string());
                        }
                    }

                    if Url::parse(original_domain.clone().as_str())
                        .unwrap()
                        .domain()
                        .unwrap()
                        != Url::parse(__domain.as_str()).unwrap().domain().unwrap()
                    {
                        if test_domain == Url::parse(__domain.as_str()).unwrap().domain().unwrap() {
                            info!(format!(" |-Vulnerable: Redirects to {__domain}"));
                            return (full_url, __domain);
                        }
                    }
                }
                403 => {
                    println!(" |-{url}: Forbidden");
                }
                _ => {}
            },
            Err(err) => {
                if err.is_timeout() {
                    warn!("Err: connection timedout");
                }
            }
        }
        return ("".to_string(), "".to_string());
    }

    pub fn test_open_redirect_async_wrapper(
        url: String,
        payload: String,
        original_domain: String,
        test_domain: &str,
    ) -> (String, String) {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        return runtime.block_on(test_single_payload(
            url,
            payload,
            original_domain,
            test_domain,
        ));
    }

    /// Entry point
    pub fn process_url(url: String) {
        let TEST_DOMAIN = "google.com";

        let PAYLOADS = [
            "//{TEST_DOMAIN}",
            "//www.{TEST_DOMAIN}",
            "https://{TEST_DOMAIN}",
            "https://www.{TEST_DOMAIN}",
            "//{TEST_DOMAIN}/%2f..",
            "https://{TEST_DOMAIN}/%2f..",
            "////{TEST_DOMAIN}",
            "https:////{TEST_DOMAIN}",
            "/\\/\\{TEST_DOMAIN}",
            "/.{TEST_DOMAIN}",
            "///\\;@{TEST_DOMAIN}",
            "///{TEST_DOMAIN}@{TEST_DOMAIN}",
            "///{TEST_DOMAIN}%40{TEST_DOMAIN}",
            "////{TEST_DOMAIN}//",
            "/https://{TEST_DOMAIN}",
            "{TEST_DOMAIN}",
        ];
        let mut parsed_original_url: String = String::new();
        let mut parsed_original_domain: String = String::new();

        if let Ok(parsed) = Url::parse(url.as_str()) {
            parsed_original_url = parsed.to_string();
            if let Some(parsed_domain) = Url::parse(url.as_str()).unwrap().domain() {
                parsed_original_domain = parsed_domain.to_string();
            }
        } else {
            warn!(format!("Invalid url {url}, Quitting..."));
            return;
        }

        let vulnerable_urls: Vec<(String, String)> = PAYLOADS
            .par_iter()
            .filter_map(|payload| {
                Some(test_open_redirect_async_wrapper(
                    url.clone(),
                    payload.to_string(),
                    parsed_original_domain.clone(),
                    TEST_DOMAIN,
                ))
            })
            .collect();
        for (fullurl, location) in vulnerable_urls {
            if fullurl.len() != 0 && location.len() != 0 {
                write_info_and_print!(" |- {} : {}", fullurl, location);
            }
        }
    }
}

pub mod automoussystemnumber {
    use crate::save_util;
    use colored::Colorize;
    use reqwest::Error;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct RipeData {
        data: Option<Prefixes>,
    }

    #[derive(Debug, Deserialize)]
    struct Prefixes {
        prefixes: Vec<Prefix>,
    }

    #[derive(Debug, Deserialize)]
    struct Prefix {
        prefix: String,
    }
    pub async fn get_ip_ranges(asn: String) -> (String, Vec<String>) {
        let url = format!("https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}");

        let Session = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(std::time::Duration::new(10, 0))
            .build()
            .unwrap_or_else(|err| {
                warn!(format!("unable to create Client Session\n{}", err));
                panic!();
            });

        match Session.get(url).send().await {
            Ok(response) => match response.json::<RipeData>().await {
                Ok(parsed_data) => {
                    if let Some(prefixes_data) = parsed_data.data {
                        let prefixes = prefixes_data
                            .prefixes
                            .into_iter()
                            .map(|p| p.prefix)
                            .collect();
                        (asn.to_string(), prefixes)
                    } else {
                        (asn.to_string(), vec![]) // No prefixes found
                    }
                }
                Err(err) => {
                    eprintln!("Error parsing data for {}: {}", asn, err);
                    (asn.to_string(), vec![])
                }
            },
            Err(err) => {
                eprintln!("Error fetching data for {}: {}", asn, err);
                (asn.to_string(), vec![])
            }
        }
    }

    pub async fn process_asn(asn: String) {
        info!(format!("Handling asn {asn}"));
        let (_, results) = get_ip_ranges(asn).await;
        if results.len() == 0 {
            println!("No Ip ranges found");
            return;
        }
        println!("IP ranges Found:");
        for i in &results {
            write_info_and_print!(" |-{}", i);
        }
    }
}
