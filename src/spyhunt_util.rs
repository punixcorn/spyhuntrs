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

use crate::{
    cmd_handlers::{self, cmd_info, run_cmd, run_cmd_string, run_piped_strings},
    file_util::{file_exists, read_from_file},
    google_search::{self},
    request, save_util,
    user_agents::get_user_agent_prexisting,
};

// above all
use {
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
pub async fn enumerate_domain(domain: &str) -> Option<()> {
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
        info!(data);
        handle_data!(data, String);
        return Some(());
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

pub mod check_cors_misconfig {
    use {
        crate::{request, save_util},
        colored::Colorize,
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
mod javascript {
    use {
        crate::{request, save_util},
        colored::Colorize,
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
    pub fn crawl_website(urls: Vec<String>) -> Option<()> {
        /*
         * i will use tokio::Semaphore later when i grasp it
         */
        if urls.is_empty() {
            return None;
        }

        let results: Vec<HashMap<&String, (Vec<String>, Vec<String>)>> = urls
            .par_iter()
            .filter_map(|url| {
                let domain: Option<String> = match reqwest::Url::parse(url.as_str()) {
                    Ok(_url) => match _url.domain() {
                        Some(d) => Some(d.to_string()),
                        _ => None,
                    },
                    Err(_) => None,
                };
                let data =
                    get_js_links_async_wrapper(url.to_string(), Some("".to_string()).clone());
                Some(HashMap::from([(url, (data))]))
            })
            .collect();

        for hashmap in results {
            for (url, vecs) in hashmap {
                info_and_handle_data!(format!("url :{url}"), String);
                if vecs.0.is_empty() {
                    println!("no javascript files found")
                } else {
                    println!(" *Javascript Files");
                    for _js_files in vecs.0 {
                        println!(" |-{}", _js_files);
                        handle_data!(format!(" |-{}", _js_files), String);
                    }
                }
                if vecs.1.is_empty() {
                    println!("no javascript files found")
                } else {
                    println!(" *Javascript Links");
                    for _js_links in vecs.1 {
                        println!(" |-{}", _js_links);
                        handle_data!(format!(" |-{}", _js_links), String);
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
    use crate::save_util;
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

/// This does exactly what `enumerate_domain(...)` does.
/// It literally just finds a title in the html
/// And Appends it, which would be better off just doing
/// That in `enumerate_domain(...)`
pub async fn domain_info(domain: &str) -> Option<()> {
    return enumerate_domain(domain).await;
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

    pub fn scan_all_ports(ip: String) -> Vec<u16> {
        info!(format!("Scanning {ip}"));
        let ports: Vec<u16> = (1..=65535).collect();
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

    pub fn cidr_notation(ip: &str) {
        let network = Ipv4Cidr::from_str(ip).unwrap();
        let ips: Vec<_> = network.iter().map(|ip| ip.to_string()).collect::<Vec<_>>();

        let open_ports: Vec<(String, Vec<u16>)> = ips
            .into_par_iter()
            .filter_map(|ip| {
                let _open_ports = scan_all_ports(ip.clone());
                Some((ip.clone(), _open_ports))
            })
            .filter(|_open_ports| !_open_ports.1.is_empty())
            .collect();

        if open_ports.is_empty() {
            warn!("no open ports found");
        } else {
            for found in &open_ports {
                handle_data!(format!("{}", found.0), String);
                for __port in &found.1 {
                    handle_data!(format!(" |-{}", __port), String);
                }
            }
        }
    }
}

pub fn print_all_ips(ip: &str) -> Option<()> {
    let network = Ipv4Cidr::from_str(ip).unwrap();
    let ips: Vec<_> = network.iter().map(|ip| ip.to_string()).collect::<Vec<_>>();
    info_and_handle_data!(format!("{ip} Extracted IP's"), String);
    for _ip in &ips {
        println!(" |-{_ip}");
        handle_data!(format!(" |-{ip}"), String);
    }
    Some(())
}

pub mod xss_scan {
    use crate::{file_util, request, save_util, spyhunt_util};
    use colored::Colorize;
    use core::fmt;
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

    /// This is so rayon can handle async
    pub fn xss_scan_url_async_wrapper(domain: String, payloads: Vec<String>) -> Vec<Vuln> {
        let _runtime = tokio::runtime::Runtime::new().unwrap();
        _runtime.block_on(xss_scan_url(domain, payloads))
    }

    /// this takes in a  Vec of target because its multithreaded
    pub fn xxs_scanner(targets: Vec<String>) -> Option<()> {
        // read file
        let payloads: Vec<String> = file_util::read_from_file("./payloads/xss.txt".to_string())
            .unwrap_or_else(|_| {
                warn!("Could not read from file payloads/xss.txt,exiting");
                [].to_vec()
            });
        if payloads.len() == 0 {
            return None;
        }

        info!("This might take a while please wait...");
        let __Vulns: Vec<(String, Vec<Vuln>)> = targets
            .par_iter()
            .filter_map(|_target| {
                let list = xss_scan_url_async_wrapper(_target.clone(), payloads.clone());
                Some((_target.clone(), list))
            })
            .collect::<Vec<(String, Vec<Vuln>)>>();

        if __Vulns.is_empty() {
            warn!("Could not find any payload injection");
            return Some(());
        }

        for ___vuln in &__Vulns {
            info!(format!("{}", ___vuln.0));
            for ____vulns in &___vuln.1 {
                handle_data!(format!("{}", ____vulns), String);
                println!("{}", ____vulns);
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
            check_if_save, file_util::read_from_file, request, save_util, spyhunt_util::xss_scan,
            user_agents::get_user_agent_prexisting,
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
        let mut payloads: Vec<String> =
            read_from_file("./payloads/sqli.txt".to_string()).unwrap_or([].to_vec());

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
            warn!("Could not find any payload injection");
            return Some(());
        }

        for ___vuln in &_vulnerabilities {
            info!(format!("{}", ___vuln.0));
            for ____vulns in &___vuln.1 {
                handle_data!(format!("{}", ____vulns), String);
                println!("{}", ____vulns);
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
            println!("{:#?}", file);
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
        }

        for (url, vec) in results {
            info_and_handle_data!(url, String);
            if vec.is_empty() {
                warn!("No results found");
            } else {
                for i in vec {
                    println!(" |-{}", i);
                    handle_data!(format!(" |-{}", i), String);
                }
            }
        }
    }
}

pub mod param_miner {
    use std::collections::HashMap;

    use super::xss_scan;
    use crate::{
        file_util::{file_exists, read_from_file},
        request::urljoin,
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
                    let strr = format!(" |-{}: {}", res.0, get_param_miner_str(res.1));
                    handle_data!(strr.clone(), String);
                    println!("{}", strr);
                }
            };
        }
        Some(())
    }
}

/// not trusted
pub fn haveibeenpwned() {}
