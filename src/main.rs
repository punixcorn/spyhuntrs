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

use std::{
    fmt::format,
    fs::read,
    time::{self, Instant},
};

use {
    colored::Colorize,
    rayon::prelude::*,
    reqwest::{dns::Resolve, header, ClientBuilder, Response},
    save_util::{check_if_save, get_save_file, save_string, save_vec_strs, set_save_file},
    serde_json::to_string,
    std::{
        env::{self, args},
        error::Error,
        process::exit,
        sync::{Arc, Mutex},
    },
};

use clap::{command, Args};
// requires
use clap::Subcommand;

/// handles the save option state
pub static Save: Mutex<bool> = Mutex::new(false);
pub static save_file: Mutex<String> = Mutex::new(String::new());

mod logging;
// comment for auto formatter to put macros in logging above the others
mod handle_deps;
mod tests;
// comment for auto formatter to put  tests & handle_deps the others
mod save_util;
// save to file
mod banner;
mod cmd_handlers;
mod favicon;
mod file_util;
mod google_search;
mod install;
mod pathhunt;
mod request;
mod spyhunt_util;
mod user_agents;
mod waybackmachine;

use clap::{ArgGroup, Parser};
use google_search::v1::setup_proxy;
use spyhunt_util::{
    brokenlinks, check_cors_misconfig::run_cors_misconfig_tokio, check_host_header_injection, dns,
    get_favicon_hash, google, ip_addresses, network_analyzer, nuclei_lfi, parse_for_domains, probe,
    shodan_api, subdomain_finder, xss_scan,
};

#[derive(Parser, Debug)]
#[command(name = "spyhuntrs")]
#[command(author = "punixcorn <cookedpotato663@gmail.com>")]
#[command(version = "0.1")]
#[command(
    about = "A comprehensive security tool",
    long_about = r#"spyhunt but with a better save feature and built (poorly) in rust 
    This is not a replacement for spyhunt(yet)
    Nor was it built to be;
    You are advised to use the original Spyhunt @ https://github.com/gotr00t0day/spyhunt
    As this doesn't have all of it's features (yet)
    And is not properly tested and documented.
    "#
)]
struct opt {
    #[arg(
        long = "save",
        visible_alias = "sv",
        value_name = "filename.txt",
        help = "Save output to file"
    )]
    save: Option<String>,

    #[arg(
        short = 'w',
        long = "wordlist",
        value_name = "filename.txt",
        help = "Wordlist to use",
        group = "_wordlist"
    )]
    wordlist: Option<String>,

    // #[arg(long = "threads", value_name = "25", help = "Default 25")]
    // threads: Option<String>,
    #[arg(long = "test")]
    test: Option<String>,

    #[arg(
        short = 's',
        value_name = "domains.txt or domain.com",
        help = "Scan for subdomains from a file of subdomains of a subdomain"
    )]
    scan: Option<String>,

    #[arg(
        short = 't',
        long = "tech",
        value_name = "domains.txt | domain.com",
        help = "Find technologies"
    )]
    tech: Option<String>,

    #[arg(
        short = 'd',
        long = "dns",
        value_name = "domains.txt | domain.com",
        help = "Scan a list of domains for DNS records"
    )]
    dns: Option<String>,

    #[arg(
        long = "probe",
        value_name = "domains.txt | domain.com",
        help = "Probe domains"
    )]
    probe: Option<String>,

    #[arg(
        long = "redirects",
        value_name = "domains.txt | domain.com",
        help = "Links getting redirected"
    )]
    redirects: Option<String>,

    #[arg(
        long = "open_redirects",
        visible_alias = "or",
        value_name = "domains.txt | domain.com",
        help = "Checks for Open redirect"
    )]
    open_redirect: Option<String>,

    #[arg(
        long = "brokenlinks",
        short = 'b',
        value_name = "domains.txt | domain.com",
        help = "Search for broken links"
    )]
    brokenlinks: Option<String>,

    #[arg(
        long = "paramspider",
        value_name = "domains.txt | domain.com",
        help = "Extract parameters from a domain"
    )]
    paramspider: Option<String>,

    #[arg(
        long = "waybackurls",
        value_name = "https://domain.com",
        help = "Scan for waybackurls"
    )]
    waybackurls: Option<String>,

    #[arg(
        long = "javascript",
        short = 'j',
        value_name = "domains.txt | domain.com",
        help = "Find JavaScript files"
    )]
    javascript: Option<String>,

    #[arg(
        long = "javascript_endpoint",
        visible_alias = "je",
        value_name = "domains.txt | domain.com",
        help = "Find JavaScript endpoints"
    )]
    javascript_endpoints: Option<String>,

    #[arg(
        long = "webcrawler",
        visible_alias = "wc",
        value_name = "domains.txt | domain.com",
        help = "Scan for URLs and JS files"
    )]
    webcrawler: Option<String>,

    #[arg(
        long = "favicon",
        visible_alias = "fi",
        value_name = "https://domain.com",
        help = "Get favicon hashes"
    )]
    favicon: Option<String>,

    #[arg(
        long = "networkanalyzer",
        value_name = "domains.txt | https://domain.com",
        help = "Net analyzer"
    )]
    networkanalyzer: Option<String>,

    #[arg(
        long = "reverseip",
        value_name = "ip | ip.txt",
        help = "Reverse IP lookup"
    )]
    reverseip: Option<String>,

    #[arg(
        long = "statuscode",
        value_name = "domains.txt | domain.com",
        help = "Get status code"
    )]
    statuscode: Option<String>,

    #[arg(
        long = "pathhunt",
        visible_alias = "ph",
        value_name = "domain.txt | domain.com?id=",
        help = "Check for directory traversal"
    )]
    pathhunt: Option<String>,

    #[arg(
        long = "corsmisconfig",
        visible_alias = "co",
        value_name = "domains.txt",
        help = "Check for CORS misconfiguration"
    )]
    corsmisconfig: Option<String>,

    #[arg(
        long = "hostheaderinjection",
        visible_alias = "hh",
        value_name = "domain.com",
        help = "Host header injection",
        requires = "_proxy"
    )]
    hostheaderinjection: Option<String>,

    #[arg(
        long = "securityheaders",
        value_name = "domain.com",
        help = "Scan for security headers"
    )]
    securityheaders: Option<String>,

    #[arg(
        long = "enumeratedomain",
        value_name = "domains.txt | domain.com",
        help = "Enumerate domains"
    )]
    enumeratedomain: Option<String>,

    #[arg(
        long = "smuggler",
        value_name = "domain.com",
        help = "Check HTTP smuggling"
    )]
    smuggler: Option<String>,

    #[arg(
        long = "ipaddresses",
        value_name = "domain-list.txt | domain.com",
        help = "Get IPs from a list of domains or a domain"
    )]
    ipaddresses: Option<String>,

    #[arg(
        long = "domaininfo",
        value_name = "domain-list.txt | domain.com",
        help = "Get domain information"
    )]
    domaininfo: Option<String>,

    #[arg(
        long = "importantsubdomains",
        value_name = "domain-list.txt",
        help = "Extract interesting subdomains"
    )]
    importantsubdomains: Option<String>,

    #[arg(
        long = "not_found",
        value_name = "domains.txt",
        help = "Check for 404 status codes"
    )]
    not_found: Option<String>,

    #[arg(
        long = "nmap",
        value_name = "domain.com or IP",
        help = "Scan a target with Nmap"
    )]
    nmap: Option<String>,

    #[arg(
        long = "api_fuzzer",
        value_name = "domain-list.txt | domain.com",
        help = "Look for API endpoints"
    )]
    api_fuzzer: Option<String>,

    #[arg(
        long = "shodan",
        value_name = "domain.com",
        help = "Recon with Shodan",
        requires = "_shodanapi"
    )]
    shodan: Option<String>,

    #[arg(
        long = "shodanapi",
        value_name = "API-KEY",
        help = "Add Shodan api key",
        group = "_shodanapi"
    )]
    shodanapi: Option<String>,

    #[arg(
        long = "forbiddenpass",
        value_name = "domain.com",
        help = "Bypass 403 forbidden"
    )]
    forbiddenpass: Option<String>,

    #[arg(
        long = "directorybrute",
        value_name = "domain-list.txt | domain.com",
        help = "Brute force directories",
        requires = "_wordlist"
    )]
    directorybrute: Option<String>,

    #[arg(
        long = "cidr_notation",
        value_name = "IP/24",
        help = "Scan an IP range",
        requires = "_port"
    )]
    cidr_notation: Option<String>,

    #[arg(
        long = "ports",
        value_name = "80,443,8443 | ALL ",
        help = "Ports to scan",
        group = "_port"
    )]
    ports: Option<String>,

    #[arg(long = "print_all_ips", value_name = "IP/24", help = "Print all IPs")]
    print_all_ips: Option<String>,

    #[arg(
        long = "xss_scan",
        visible_alias = "xss",
        value_name = "domains.txt | domain.com?id=1",
        help = "Scan for XSS vulnerabilities"
    )]
    xss_scan: Option<String>,

    #[arg(
        long = "sqli_scan",
        visible_alias = "sqli",
        value_name = "domains.txt | domain.com?id=1",
        help = "Scan for SQLi vulnerabilities"
    )]
    sqli_scan: Option<String>,

    #[arg(long = "s3-scan", help = "Scan for exposed S3 buckets")]
    s3_scan: bool,

    // #[arg(long = "verbose", help = "Increase output verbosity")]
    // verbose: bool,
    //
    // #[arg(
    //     long = "concurrency",
    //     default_value_t = 10,
    //     help = "Maximum number of concurrent requests"
    // )]
    // concurrency: usize,
    #[arg(long = "nuclei_lfi", help = "Find Local File Inclusion with nuclei", action = clap::ArgAction::Count)]
    nuclei_lfi: u8,

    #[arg(
        long = "google",
        value_name = "query | domain.com",
        help = "Perform Google Search on a query and get relevant data"
    )]
    google: Option<String>,

    #[arg(long = "update", help = "install dependices" , action = clap::ArgAction::Count)]
    install: u8,

    #[arg(
        long = "proxy",
        value_name = "URL",
        help = "Use a proxy",
        group = "_proxy"
    )]
    proxy: Option<String>,

    #[arg(
        long = "proxy-file",
        value_name = "file.txt",
        help = "Load proxies from a file",
        group = "_proxy"
    )]
    proxy_file: Option<String>,
    // #[arg(
    //     long = "output-dir",
    //     default_value = ".",
    //     help = "Specify output directory"
    // )]
    // output_dir: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    banner::print_banner();
    let mut wordlist: String = String::new();
    let mut proxies: String = String::new();
    let mut is_proxy_file: bool = false;
    if env::args().count() <= 1 {
        warn!("No options passed\ntry --help for more information");
        exit(1);
    } else {
        let args = opt::parse();

        match args.save {
            Some(filename) => {
                save_util::set_save_file(&filename);
                save_util::set_save_option(true);
            }
            None => {}
        }
        match args.wordlist {
            Some(filename) => {
                info!(format!("Using wordlist: {}", filename));
                wordlist = filename;
            }
            None => {}
        }

        match args.proxy {
            Some(prox) => {
                proxies = prox;
                is_proxy_file = false;
            }
            None => {}
        }

        match args.proxy_file {
            Some(prox) => {
                proxies = prox;
                is_proxy_file = true;
            }
            None => {}
        }

        match args.nmap {
            Some(domain) => {
                spyhunt_util::nmap(domain);
            }
            None => {}
        }

        match args.scan {
            Some(target) => {
                let domains = parse_for_domains(target);
                info!(format!("Scanning subdomains"));
                subdomain_finder(domains).await;
            }
            None => {
                println!("No domain or file provided for subdomain scan.");
            }
        }

        match args.tech {
            Some(domain) => {
                let domains = parse_for_domains(domain.clone());
                info!(format!("Finding technologies on: {}", domain));
                spyhunt_util::tech::find_tech_main(domains);
            }
            None => {}
        }

        match args.dns {
            Some(file_or_domain) => {
                info!(format!("Scanning DNS records from {}", file_or_domain));
                let domains = parse_for_domains(file_or_domain);
                for i in domains {
                    dns(i);
                }
            }
            None => {}
        }

        match args.probe {
            Some(file_or_domain) => {
                let domains = parse_for_domains(file_or_domain.clone());
                info!(format!("Probing domains in file: {}", file_or_domain));
                for domain in domains {
                    probe(domain);
                }
            }
            None => {}
        }

        match args.redirects {
            Some(file_or_domain) => {
                let domains = parse_for_domains(file_or_domain.clone());
                info!(format!("Probing domains in file: {}", file_or_domain));
                for domain in domains {
                    spyhunt_util::redirects(domain);
                }
            }
            None => {}
        }

        match args.open_redirect {
            Some(file_or_domain) => {
                info!(format!(
                    "Scanning domains for open redirect: {}",
                    file_or_domain
                ));
                for url in parse_for_domains(file_or_domain) {
                    spyhunt_util::open_redirect::process_url(url);
                }
            }
            None => {}
        }

        match args.brokenlinks {
            Some(file_or_domain) => {
                info!(format!(
                    "Searching for broken links in: {}",
                    file_or_domain.clone()
                ));
                let domains = parse_for_domains(file_or_domain);

                for domain in domains {
                    brokenlinks(domain);
                }
            }
            None => {}
        }

        match args.paramspider {
            Some(file_or_domain) => {
                info!(format!("Extracting parameters from: {}", file_or_domain));
                for domain in parse_for_domains(file_or_domain) {
                    spyhunt_util::paramspider(domain);
                }
            }
            None => {}
        }

        match args.waybackurls {
            Some(url) => {
                info!(format!("Scanning Wayback URLs for: {}", url));
                spyhunt_util::wayback_urls(url.clone());
            }
            None => {}
        }

        match args.javascript {
            Some(file_or_domain) => {
                info!(format!("Finding JavaScript files on: {}", file_or_domain));
                let domains = parse_for_domains(file_or_domain);
                spyhunt_util::javascript::crawl_website(domains);
            }
            None => {}
        }
        match args.javascript_endpoints {
            Some(file_or_domain) => {
                info!(format!("Finding JavaScript endpoints..."));
                let domains = parse_for_domains(file_or_domain);
                spyhunt_util::javascript_endpoints::process_js_files(domains).await;
            }
            None => {}
        }

        match args.webcrawler {
            Some(file_or_domain) => {
                info!(format!("Crawling URLs and JS files on: {}", file_or_domain));
                let domains = parse_for_domains(file_or_domain);
                spyhunt_util::webcrawler(domains);
            }
            None => {}
        }

        match args.favicon {
            Some(url) => {
                info!(format!("Getting favicon hash for: {}", url));
                get_favicon_hash(url).await;
            }
            None => {}
        }

        match args.networkanalyzer {
            Some(file_or_domain) => {
                info!(format!(
                    "Performing network analysis on: {}",
                    file_or_domain
                ));
                for domain in parse_for_domains(file_or_domain) {
                    network_analyzer(domain);
                }
            }
            None => {}
        }

        match args.reverseip {
            Some(file_or_domain) => {
                info!(format!(
                    "Performing reverse IP lookup for: {}",
                    file_or_domain
                ));
                let domains = parse_for_domains(file_or_domain);
                ip_addresses(domains);
            }
            None => {}
        }

        match args.statuscode {
            Some(file_or_domain) => {
                info!(format!("Getting status code for: {}", file_or_domain));
                let domains = parse_for_domains(file_or_domain);
                spyhunt_util::status_code::run_status_code_tokio(domains).await;
            }
            None => {}
        }

        match args.pathhunt {
            Some(file_or_domain) => {
                info!(format!(
                    "Checking directory traversal in: {}",
                    file_or_domain
                ));
                let domains = parse_for_domains(file_or_domain);
                pathhunt::scan_target_tokio(domains).await;
            }
            None => {}
        }

        match args.corsmisconfig {
            Some(file_or_domain) => {
                info!(format!(
                    "Checking for CORS misconfiguration in: {}",
                    file_or_domain.clone()
                ));
                let domains = parse_for_domains(file_or_domain);
                run_cors_misconfig_tokio(domains).await;
            }
            None => {}
        }

        match args.hostheaderinjection {
            Some(domain) => {
                info!(format!("Performing host header injection on: {}", domain));
                check_host_header_injection(domain, proxies, is_proxy_file).await;
            }
            None => {}
        }

        match args.securityheaders {
            Some(domain) => {
                info!(format!("Scanning security headers for: {}", domain));
                spyhunt_util::check_security_headers(domain).await;
            }
            None => {}
        }

        match args.enumeratedomain {
            Some(file_or_domain) => {
                info!(format!("Enumerating domains for: {}", file_or_domain));
                let domains = parse_for_domains(file_or_domain);

                spyhunt_util::enumerate_domain::enumerate_domain_tokio(domains).await;
            }
            None => {}
        }

        match args.smuggler {
            Some(domain) => {
                info!(format!("No Checking for HTTP smuggling on: {}", domain));
                warn!("NOT IMPLEMENTED");
            }
            None => {}
        }

        match args.ipaddresses {
            Some(file_or_domain) => {
                info!(format!("Extracting IPs from file: {}", file_or_domain));
                let domains = parse_for_domains(file_or_domain.clone());
                ip_addresses(domains);
            }
            None => {}
        }

        match args.domaininfo {
            Some(file_or_domain) => {
                info!(format!("Getting domain info from file: {}", file_or_domain));
                let domains = parse_for_domains(file_or_domain);
                spyhunt_util::domain_info(domains).await;
            }
            None => {}
        }

        match args.importantsubdomains {
            Some(file) => {
                info!(format!("Extracting important domains..."));
                spyhunt_util::importantsubdomains(file);
            }
            None => {}
        }
        match args.not_found {
            Some(file) => {
                info!(format!("Looking for Dead endpoints..."));
                spyhunt_util::find_not_found(file).await;
            }
            None => {}
        }
        match args.api_fuzzer {
            Some(file_or_domain) => {
                info!(format!("Look for Api Endpoints"));
                let domains = parse_for_domains(file_or_domain);
                spyhunt_util::api_fuzzer::api_fuzzer_tokio(domains).await;
            }
            None => {}
        }
        let mut shodan_api_key = String::new();
        match args.shodanapi {
            Some(api) => {
                shodan_api_key = api;
            }
            None => {}
        }
        match args.shodan {
            Some(file_or_domain) => {
                info!(format!("Finding subdomains through shodan"));
                if shodan_api_key.len() == 0 {
                    warn!("No api key passed use --shodanapi");
                } else {
                    let domains = parse_for_domains(file_or_domain);
                    for domain in domains {
                        shodan_api(shodan_api_key.clone(), domain, false).await;
                    }
                }
            }
            None => {}
        }

        match args.forbiddenpass {
            Some(domain) => {
                info!(format!("Attempting bypass on  {domain}"));
                spyhunt_util::forbiddenpass::forbiddenpass(domain).await;
            }
            None => {}
        }

        match args.directorybrute {
            Some(file_or_domain) => {
                info!(format!("Attempting bypass on  {file_or_domain}"));
                let domains = parse_for_domains(file_or_domain);
                spyhunt_util::run_directory_brute_threads(domains, wordlist, Vec::new());
            }
            None => {}
        }

        // match args.cidr_notation {
        //     Some(Ip) => {
        //         info!(format!("Scanning for Ip's and ports on  network {Ip}"));
        //         spyhunt_util::cidr_notation::cidr_notation(Ip.as_str());
        //     }
        //     None => {}
        // }

        match args.cidr_notation {
            Some(Ip) => {
                let mut Ports: Vec<u16> = Vec::new();
                let mut trip_all: bool = false;

                match args.ports {
                    Some(_ports) => {
                        if _ports.to_lowercase() == "all" {
                            trip_all = true;
                        } else {
                            let _vec: Vec<_> = _ports.split(',').collect();
                            for i in _vec {
                                Ports.push(i.parse::<u16>().unwrap());
                            }
                        }
                    }
                    None => {
                        err!("Could not Parse Ports:\nUse Example: --port 12,23,80  | --port all");
                    }
                }

                info!(format!(
                    "Scanning for Ip's and ports on  network {}",
                    Ip.clone()
                ));
                if trip_all && Ports.is_empty() {
                    spyhunt_util::cidr_notation::cidr_notation(Ip.clone(), None);
                } else {
                    spyhunt_util::cidr_notation::cidr_notation(Ip.clone(), Some(Ports));
                }
            }
            None => {}
        }

        match args.print_all_ips {
            Some(Ip) => {
                info!(format!("Getting all ip from {}", Ip.clone()));
                spyhunt_util::print_all_ips(Ip.as_str());
            }
            None => {}
        }

        match args.xss_scan {
            Some(file_or_domain) => {
                info!(format!("Running XSS scan on {}", file_or_domain.clone()));
                let domains = parse_for_domains(file_or_domain);
                spyhunt_util::xss_scan::xxs_scanner(domains);
            }
            None => {}
        }
        match args.sqli_scan {
            Some(file_or_domain) => {
                info!(format!("Running SQLi scan on {}", file_or_domain.clone()));
                let domains = parse_for_domains(file_or_domain);
                spyhunt_util::sqli_scan::sqli_scanner(domains);
            }
            None => {}
        }

        match args.nuclei_lfi {
            0 => {}
            _ => {
                info!("Starting Nuclei....");
                nuclei_lfi();
            }
        }

        match args.google {
            Some(query) => {
                info!(format!("Running Google search on {}....", query.clone()));
                google(query).await;
            }
            None => {}
        }
        match args.install {
            0 => {}
            _ => {
                warn!(format!("EXPERIMENTAL DON'T"));
                install::install();
            }
        }

        match args.test {
            Some(x) => {
                let mut finish = std::time::Duration::from_secs(0);
                let domains: Vec<String> = vec![
                    "google.com".to_string(),
                    "youtube.com".to_string(),
                    "facebook.com".to_string(),
                    "instagram.com".to_string(),
                    "whatsapp.com".to_string(),
                    "x.com".to_string(),
                    "wikipedia.org".to_string(),
                    "chatgpt.com".to_string(),
                    "reddit.com".to_string(),
                    "yahoo.com".to_string(),
                    "yahoo.co.jp".to_string(),
                    "amazon.com".to_string(),
                    "yandex.ru".to_string(),
                    "baidu.com".to_string(),
                    "tiktok.com".to_string(),
                    "netflix.com".to_string(),
                    "microsoftonline.com".to_string(),
                    "bing.com".to_string(),
                    "pornhub.com".to_string(),
                    "linkedin.com".to_string(),
                    "live.com".to_string(),
                    "naver.com".to_string(),
                    "dzen.ru".to_string(),
                    "office.com".to_string(),
                    "microsoft.com".to_string(),
                    "xvideos.com".to_string(),
                    "pinterest.com".to_string(),
                    "bilibili.com".to_string(),
                    "twitch.tv".to_string(),
                    "vk.com".to_string(),
                    "news.yahoo.co.jp".to_string(),
                    "xhamster.com".to_string(),
                    "mail.ru".to_string(),
                    "sharepoint.com".to_string(),
                    "samsung.com".to_string(),
                    "fandom.com".to_string(),
                    "globo.com".to_string(),
                    "canva.com".to_string(),
                    "xnxx.com".to_string(),
                    "duckduckgo.com".to_string(),
                    "t.me".to_string(),
                    "weather.com".to_string(),
                    "quora.com".to_string(),
                    "temu.com".to_string(),
                    "cnn.com".to_string(),
                    "zoom.us".to_string(),
                    "stripchat.com".to_string(),
                    "ebay.com".to_string(),
                ];
                let domains2: Vec<String> = domains.clone();
                println!("[TEST] {}", "RUNNING TOKIO::SPAWN".yellow());
                let mut start = Instant::now();
                spyhunt_util::status_code::run_status_code_tokio(domains).await;
                finish = start.elapsed();
                println!("TIME : {}", finish.as_secs_f64());
                println!("[TEST] {}", "RUNNING RAYON".yellow());
                start = Instant::now();
                spyhunt_util::status_code::rayon_status_code(domains2);
                finish = start.elapsed();
                println!("TIME : {}", finish.as_secs_f64());
                println!("{}", "TESTS DONE, goodbye...".green());
                exit(0);
            }
            None => {}
        }
    }

    Ok(())
}
