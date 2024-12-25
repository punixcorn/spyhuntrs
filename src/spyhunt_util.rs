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
    cmd_handlers::{self, cmd_info, run_cmd_string, run_piped_strings},
    file_util::{file_exists, read_from_file},
    request,
    save_util::{self, check_if_save, get_save_file, save_string, save_vec_strs, set_save_file},
};
// above all
use {
    base64::{
        alphabet,
        engine::{self, general_purpose},
        Engine as _,
    },
    colored::Colorize,
    dns_lookup::lookup_addr,
    murmur3::murmur3_32,
    murmur3::murmur3_x64_128,
    rand::random,
    rayon::prelude::*,
    reqwest::{dns::Resolve, header, ClientBuilder, Response},
    reqwest::{header::HeaderValue, Proxy},
    serde::{de::IntoDeserializer, Deserializer},
    shodan_client::*,
    soup::pattern::Pattern,
    std::{clone, process::Output},
    std::{
        error::Error,
        fmt::format,
        net::{IpAddr, SocketAddr},
        path::{self, Path, PathBuf},
        str::{FromStr, SplitTerminator},
        string,
        sync::{Arc, Mutex},
    },
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
            let x = srt
                .stdout
                .clone()
                .unwrap_or_else(|| format!("{domain} [err]"));
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

/// get the favicon hash for a domain [completed]
/// # Issue
/// dunno how this works ?
/// maybe just get the image and look ??
/// because it could have been changed? plus hashes don't match
pub async fn get_favicon_hash(domain: String) -> Option<()> {
    let new_url = request::urljoin(domain.clone(), "/favicon.ico".to_string());
    let resp = fetch_url!(new_url.clone());
    println!("{:#?}", resp);
    match resp {
        Ok(body) => {
            if body.status().is_success() {
                let mut base_64 = general_purpose::STANDARD.encode(body.bytes().await.unwrap());
                // let hash = murmur3_32(&mut std::io::Cursor::new(base_64), 0).unwrap();
                let hash = (murmurhash3::murmurhash3_x86_32(base_64.as_bytes(), 0)) as i32;
                info!(format!("{domain} favicon hash : [{hash}]"));
                handle_data!(format!("{domain} favicon hash : [{hash}]"), String);
                return Some(());
            }
            warn!(format!("could not find favicon for {}", domain.clone()));
            return None;
        }
        _ => {
            warn!(format!("could not find favicon for {}", domain.clone()));
            return None;
        }
    }
}

/// checks for cors misconfiguration for a domain [completed]
/// # Example
/// ```rust
/// check_cors_misconfig("www.example.com");
/// ```
/// # panic
/// will panic if its unable to create a client
pub fn check_cors_misconfig(domain: &str) -> () {
    let payload = format!("{domain}, evil.com");

    let client = reqwest::blocking::Client::builder()
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
    let mut resp: reqwest::blocking::Response;
    match client
        .get(request::urljoin(domain.to_string(), "".to_string()))
        .headers(headers)
        .send()
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
    info!(format!("{vuln_status}: {domain}"));
    handle_data!(format!("{vuln_status} : {domain}"), String);
}

/// checks for cors misconfiguration in parallel using rayon [completed]
pub async fn run_cors_misconfig_threads(domains: Vec<&str>) -> () {
    domains.par_iter().for_each(|&domain| {
        {
            info!(format!("Checking CORS for {}", domain));
            //std::thread::sleep(std::time::Duration::from_secs(1));
            check_cors_misconfig(domain);
            info!(format!("Checked: {}", domain));
        }
    });
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

    let proxy = setup_proxies(proxy, is_proxy_file).unwrap();

    let mut curr_proxy: Proxy;

    // this is ignored, throw an error if a proxy doesn't exist
    // if !proxy.is_empty() {
    //     curr_proxy = reqwest::Proxy::http(proxy[0].clone()).unwrap();
    // };
    //

    // make this fetch a random proxy
    curr_proxy = reqwest::Proxy::http(proxy[0].clone()).unwrap();

    let client = reqwest::Client::builder()
        .proxy(curr_proxy)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(std::time::Duration::new(5, 0))
        .build()
        .unwrap_or_else(|err| {
            warn!(format!("unable to create Client Session\n{}", err));
            panic!();
        });

    let normal_response_text: String = client
        .get(request::urljoin(domain.clone(), "".to_string()))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

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
                                        warn!(format!("{domain} : fetching string vaule from Location header failed"));
                                    }
                                };
                            }
                            _ => {
                                warn!(format!("{domain} : No Location header found"));
                            }
                        };
                    }
                    _ => {
                        warn!(format!("{domain} : failed to retrieve response code"));
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
                        info!(format!(
                            "{domain} : Found Security Header {}",
                            security_headers[0]
                        ));
                        handle_data!(format!("{domain} : {}", security_headers[0]), String);
                    }
                    "content-security-policy" => {
                        info!(format!(
                            "{domain} : Found Security Header {}",
                            security_headers[0]
                        ));
                        handle_data!(format!("{domain} : {}", security_headers[1]), String);
                    }
                    "x-frame-options" => {
                        info!(format!(
                            "{domain} : Found Security Header {}",
                            security_headers[0]
                        ));
                        handle_data!(format!("{domain} : {}", security_headers[2]), String);
                    }
                    "x-content-type-options" => {
                        info!(format!(
                            "{domain} : Found Security Header {}",
                            security_headers[0]
                        ));
                        handle_data!(format!("{domain} : {}", security_headers[3]), String);
                    }
                    "x-xss-protection" => {
                        info!(format!(
                            "{domain} : Found Security Header {}",
                            security_headers[0]
                        ));
                        handle_data!(format!("{domain} : {}", security_headers[4]), String);
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
                info!(format!("{out}"));
                handle_data!(format!("{out}"), String);
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
                info!(format!("{out}"));
                handle_data!(format!("{out}"), String);
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
                info!(format!("{out}"));
                handle_data!(format!("{out}"), String);
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
mod javascript {}

/// run a dns scan on domain
pub fn dns(domain: String) {
    let commands: Vec<_> = vec!["-ns -resp", "-cname -resp", "-a -resp"];
    let mut place = 0;
    for cmd in &commands {
        match place {
            0 => {
                info!("Printing A records");
                handle_data!(format!("{domain}: A records"), String);
            }
            1 => {
                info!("Printing NS records");
                handle_data!(format!("{domain}: NS records"), String);
            }
            2 => {
                info!("Printing CNAME records");
                handle_data!(format!("{domain}: CNAME records"), String);
            }
            _ => {}
        };
        match run_piped_strings(format!("echo {}", domain), format!("dnsx -slient {}", cmd)) {
            Some(data) => match data.stdout {
                Some(out) => {
                    info!(format!("{out}"));
                    handle_data!(format!("{out}"), String);
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
                                    handle_data!(format!("{_stdout}"), String);
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
                                    info!(format!("{_stdout}"));
                                    handle_data!(format!("{_stdout}"), String);
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
                info!(format!("{out}"));
                handle_data!(format!("{out}"), String);
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
    use crate::save_util::{self, check_if_save};
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
                    info_and_handle_data!(format!("{domain}"), String);
                    for i in &ds.groups {
                        println!("-{}", i.name);
                        handle_data!(format!("-{}", i.name), String);
                        for j in &i.categories {
                            println!(" |-{}", i.name);
                            handle_data!(format!(" |-{}", i.name), String);
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
}

pub fn smuggler(domain: String) {
    //smug_path
}
