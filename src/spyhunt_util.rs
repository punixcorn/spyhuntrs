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
    cmd_handlers::{self, cmd_info, run_cmd, run_cmd_string, run_piped_strings},
    file_util::{file_exists, read_from_file},
    google_search::{self},
    request,
    save_util::{self, check_if_save, get_save_file, save_string, save_vec_strs, set_save_file},
    user_agents::get_user_agent_prexisting,
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
};

/// get the domain name for the ip [ip] [Completed]
/// # Example
/// ```rust
/// get_reverse_ip(["8.8.8.8"].to_vec());
/// ```
pub fn get_reverse_ip(ip: Vec<&str>) -> Option<()> {
    for d in ip {
        let ip_addr: Result<IpAddr, _> = d.parse();
        match ip_addr {
            Ok(data) => {
                match dns_lookup::lookup_addr(&data) {
                    Ok(d_name) => {
                        info_and_handle_data!(format!("{d} {d_name}"), String);
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
pub async fn subdomain_finder(domain: Vec<&str>) -> Option<()> {
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
    Some(())
}

/// perform a webcrawl using hakrawler [completed]
pub fn webcrawler(domain: Vec<&str>) -> Option<()> {
    for d in domain {
        let cmd = cmd_handlers::run_piped_strings(format!("echo {}", d), format!("hakrawler"));
        match cmd {
            Some(data) => {
                match data.stdout {
                    Some(x) => {
                        for i in x.split('\n').into_iter() {
                            info!(format!("{}\n", i));
                            handle_data!(i, &str);
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
                    info!(format!("{}\n", x));
                    handle_data!(&x, &str);
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
    //         handle_data!(x, String);
    //     }
    //     _ => warn!(format!("err occured for {domain}")),
    // }
    Some(())
}

/// get status code of domain using reqwest [completed]
pub async fn status_code_reqwest(domain: &str) -> Option<()> {
    let d = domain.trim().replace("https://", "").replace("http://", "");
    let mut code: u16 = 0;
    let resp = fetch_url!(domain.to_string());
    match resp {
        Ok(data) => {
            info!(format!("{d} [{}]", data.status().as_u16()));
            handle_data!(format!("{d} [{}]", data.status().as_u16()), String);
        }
        Err(_) => {
            warn!(format!("{d} [no infomation]"));
            return None;
        }
    };
    Some(())
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
                        info!(format!("{d} : [{ip_v4}]"));
                        handle_data!(ip_v4, String);
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

            if importantsubs.is_empty() {
                warn!(format!("No important subdomain found"));
                return;
            }
            for i in importantsubs {
                info_and_handle_data!(format!("{i}"), String);
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
        err!(format!("{domains_file} does not exist"));
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
        warn!(format!("no 404 subdomain found"));
    }
    for sub in &not_found_domains {
        info_and_handle_data!(format!("{sub} : 404 [NOT FOUND]"), String);
    }
    Some(())
}

/// run paramspider on domain [completed]
pub fn paramspider(domain: String) -> Option<()> {
    match run_cmd_string(format!("paramspider -d {domain}")) {
        Some(data) => match data.stdout {
            Some(out) => {
                info!(format!("{out}"));
                handle_data!(format!("{out}"), String);
                match data.stderr {
                    Some(out) => {
                        if out.contains("SyntaxWarning: invalid escape sequence") {
                            for line in out.split('\n').collect::<Vec<_>>() {
                                if line.contains("SyntaxWarning: invalid escape sequence") {
                                    continue;
                                }
                                info_and_handle_data!(format!("{line}"), String);
                            }
                        }
                    }
                    None => {}
                }
            }
            None => match data.stderr {
                Some(out) => warn!(format!("stderr : {out}")),
                _ => {
                    warn!(format!(
                        "running paramspider on {} failed, no output",
                        domain.clone()
                    ));
                    return None;
                }
            },
        },
        _ => {
            warn!(format!("running paramspider on {} failed", domain.clone()));
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
                info!(format!("{out}"));
                handle_data!(format!("{out}"), String);
            }
            _ => match data.stderr {
                Some(out) => warn!(format!("stderr : {out}")),
                _ => {
                    warn!(format!(
                        "running nmap on {} failed, no output",
                        domain.clone()
                    ));
                    return None;
                }
            },
        },
        _ => {
            warn!(format!("running nmap on {} failed", domain.clone()));
            return None;
        }
    };
    Some(())
}

/// i dunno what it does that others don't do
async fn api_fuzzer(domain: String) -> Option<()> {
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

    if !file_exists(&"./payloads/api-endpoints.txt") {
        warn!("could not if payloads/api-endpoints.txt, quitting....");
        return None;
    }

    let mut found_partterns: HashMap<String, String> = HashMap::new();
    let mut existing_endpoints: Vec<String> = vec![];
    let api_endpoints: Vec<String> =
        read_from_file("./payloads/api-endpoints.txt".to_string()).unwrap();

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
                                found_partterns.insert(endpoint.to_string(), pattern.to_string());
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
                warn!(format!("{domain} : failed to fetch endpoint {endpoint}"));
            }
        };
    }

    info_and_handle_data!(format!("{domain} : Found existing endpoints"), String);
    if !existing_endpoints.is_empty() {
        for i in &existing_endpoints {
            println!(" |- {i}");
            handle_data!(format!(" |- {i}"), String);
        }
    } else {
        info!("No endpoints found");
    }

    info!(format!("{domain} : Patterns Found"));
    if !found_partterns.is_empty() {
        for (k, v) in &found_partterns {
            println!(" |- Endpoint: {k} - pattern: {v}");
            handle_data!(format!(" |- Endpoint: {k} - pattern: {v}"), String);
        }
    } else {
        info!("No Patterns found");
    }

    Some(())
}

pub mod forbiddenpass {
    use {
        crate::{
            file_util::read_from_file, get_save_file, request::urljoin, save_util,
            save_util::check_if_save, user_agents::get_user_agent_prexisting,
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
        let wordlist = read_from_file("./payloads/bypasses.txt".to_string());

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
                        info_and_handle_data!(format!("{domain} [200] : {:#?}", header), String);
                    }
                    _ => {}
                },
                Err(err) => {
                    if err.is_timeout() {
                        warn!(format!("{domain}: request Timeout"));
                    } else {
                        warn!(format!("{domain}: a request failed"));
                    }
                }
            }
        }
        Some(())
    }
} // mod forbiddenpass

// run directory bruteforce using reqwest on [domain]
// using [wordlist] with status code out of scope of [excluded_codes]
pub fn directory_brute(
    domain: String,
    wordlist: Vec<String>,
    excluded_codes: Vec<i32>,
) -> Option<()> {
    let Session = reqwest::blocking::Client::builder()
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

    for word in &wordlist {
        match Session
            .get(request::urljoin(domain.clone(), word.clone()))
            .send()
        {
            Ok(resp) => {
                match resp.status().as_u16() {
                    200 => {
                        if !excluded_codes.contains(&200) {
                            info_and_handle_data!(format!(" {word} [200]"), String);
                        }
                    }
                    302 => {
                        if !excluded_codes.contains(&302) {
                            info_and_handle_data!(format!(" {word} [302]"), String);
                        }
                    }
                    301 => {
                        if !excluded_codes.contains(&301) {
                            info_and_handle_data!(format!(" {word} [301]"), String);
                        }
                    }
                    _ => {}
                };
            }
            Err(err) => {
                if err.is_timeout() {
                    warn!(format!("{word} timedout"));
                }
            }
        };
    }
    Some(())
}

/// Runs directory bruteforce on [domain] using a wordlist file [wordlist_file]
/// and outputs all status codes out of [excluded_codes]
/// run in parallel using rayon [completed]
pub fn run_directory_brute_threads(
    domains: Vec<&str>,
    wordlist_file: String,
    excluded_codes: Vec<i32>,
) -> () {
    if !file_exists(&wordlist_file) {
        err!(format!("{wordlist_file} does not exist"));
    }
    let wordlists = read_from_file(wordlist_file).unwrap();
    domains.par_iter().for_each(|&domain| {
        {
            info!(format!("Running Directory bruteforce for {}", domain));
            //std::thread::sleep(std::time::Duration::from_secs(1));
            directory_brute(
                domain.to_string(),
                wordlists.clone(),
                excluded_codes.clone(),
            );
        }
    });
}

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
                info_and_handle_data!(format!("{data}"), String);
            }
            None => match xmd.stderr {
                Some(data) => {
                    warn!(format!("{data}"));
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
    println!("running...");
    let search = google_search::v2::user_agent::search(domain, 50).await;
    match search {
        Ok(data) => {
            for i in &data {
                info_and_handle_data!(
                    format!(
                        " |- url: {}\n |- header: {}\n |- header info: {}\n |- desc: {}\n *",
                        i.url, i.title, i.title_info, i.description
                    ),
                    String
                );
            }
        }
        Err(_) => {
            warn!("fetching google data failed");
        }
    }
    Some(())
}
