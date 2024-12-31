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
pub static Save: Mutex<bool> = Mutex::new(true);
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
mod install;
mod pathhunt;
mod request;
mod spyhunt_util;
mod user_agents;
mod waybackmachine;

use clap::{ArgGroup, Parser};

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
        value_name = "filename.txt",
        help = "Save output to file"
    )]
    save: Option<String>,

    #[arg(
        long = "wordlist",
        value_name = "filename.txt",
        help = "Wordlist to use"
    )]
    wordlist: Option<String>,

    #[arg(long = "threads", value_name = "25", help = "Default 25")]
    threads: Option<String>,

    #[arg(value_name = "domain.com", help = "Scan for subdomains")]
    scan: Option<String>,

    #[arg(long = "tech", value_name = "domain.com", help = "Find technologies")]
    tech: Option<String>,

    #[arg(
        long = "dns",
        value_name = "domains.txt",
        help = "Scan a list of domains for DNS records"
    )]
    dns: Option<String>,

    #[arg(long = "probe", value_name = "domains.txt", help = "Probe domains")]
    probe: Option<String>,

    #[arg(
        long = "redirects",
        value_name = "domains.txt",
        help = "Links getting redirected"
    )]
    redirects: Option<String>,

    #[arg(
        long = "brokenlinks",
        value_name = "domains.txt",
        help = "Search for broken links"
    )]
    brokenlinks: Option<String>,

    #[arg(
        long = "paramspider",
        value_name = "domain.com",
        help = "Extract parameters from a domain"
    )]
    paramspider: Option<String>,

    #[arg(
        long = "waybackurls",
        value_name = "https://domain.com",
        help = "Scan for waybackurls"
    )]
    waybackurls: Option<String>,

    #[arg(value_name = "domain.com", help = "Find JavaScript files")]
    javascript: Option<String>,

    #[arg(
        long = "webcrawler",
        value_name = "https://domain.com",
        help = "Scan for URLs and JS files"
    )]
    webcrawler: Option<String>,

    #[arg(
        long = "favicon",
        value_name = "https://domain.com",
        help = "Get favicon hashes"
    )]
    favicon: Option<String>,

    #[arg(
        long = "faviconmulti",
        value_name = "https://domain.com",
        help = "Get favicon hashes (multi)"
    )]
    faviconmulti: Option<String>,

    #[arg(
        long = "networkanalyzer",
        value_name = "https://domain.com",
        help = "Net analyzer"
    )]
    networkanalyzer: Option<String>,

    #[arg(long = "reverseip", value_name = "IP", help = "Reverse IP lookup")]
    reverseip: Option<String>,

    #[arg(
        long = "reverseipmulti",
        value_name = "IP",
        help = "Reverse IP lookup for multiple IPs"
    )]
    reverseipmulti: Option<String>,

    #[arg(
        long = "statuscode",
        value_name = "domain.com",
        help = "Get status code"
    )]
    statuscode: Option<String>,

    #[arg(
        long = "pathhunt",
        value_name = "domain.txt",
        help = "Check for directory traversal"
    )]
    pathhunt: Option<String>,

    #[arg(
        long = "corsmisconfig",
        value_name = "domains.txt",
        help = "Check for CORS misconfiguration"
    )]
    corsmisconfig: Option<String>,

    #[arg(
        long = "hostheaderinjection",
        value_name = "domain.com",
        help = "Host header injection"
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
        value_name = "domain.com",
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
        value_name = "domain list",
        help = "Get IPs from a list of domains"
    )]
    ipaddresses: Option<String>,

    #[arg(
        long = "domaininfo",
        value_name = "domain list",
        help = "Get domain information"
    )]
    domaininfo: Option<String>,

    #[arg(
        long = "importantsubdomains",
        value_name = "domain list",
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
        value_name = "domain.com",
        help = "Look for API endpoints"
    )]
    api_fuzzer: Option<String>,

    #[arg(long = "shodan", value_name = "domain.com", help = "Recon with Shodan")]
    shodan: Option<String>,

    #[arg(
        long = "forbiddenpass",
        value_name = "domain.com",
        help = "Bypass 403 forbidden"
    )]
    forbiddenpass: Option<String>,

    #[arg(
        long = "directorybrute",
        value_name = "domain.com",
        help = "Brute force directories"
    )]
    directorybrute: Option<String>,

    #[arg(
        long = "cidr_notation",
        value_name = "IP/24",
        help = "Scan an IP range"
    )]
    cidr_notation: Option<String>,

    #[arg(long = "ports", value_name = "80,443,8443", help = "Ports to scan")]
    ports: Option<String>,

    #[arg(long = "print_all_ips", value_name = "IP/24", help = "Print all IPs")]
    print_all_ips: Option<String>,

    #[arg(
        long = "xss_scan",
        value_name = "URL",
        help = "Scan for XSS vulnerabilities"
    )]
    xss_scan: Option<String>,

    #[arg(
        long = "sqli_scan",
        value_name = "URL",
        help = "Scan for SQLi vulnerabilities"
    )]
    sqli_scan: Option<String>,

    #[arg(long = "s3-scan", help = "Scan for exposed S3 buckets")]
    s3_scan: bool,

    #[arg(long = "verbose", help = "Increase output verbosity")]
    verbose: bool,

    #[arg(
        long = "concurrency",
        default_value_t = 10,
        help = "Maximum number of concurrent requests"
    )]
    concurrency: usize,

    #[arg(long = "nuclei_lfi", help = "Find Local File Inclusion with nuclei")]
    nuclei_lfi: bool,

    #[arg(long = "google", help = "Perform Google Search")]
    google: bool,

    #[arg(long = "update", help = "Update the script")]
    update: bool,

    #[arg(long = "proxy", value_name = "URL", help = "Use a proxy")]
    proxy: Option<String>,

    #[arg(
        long = "proxy-file",
        value_name = "file.txt",
        help = "Load proxies from a file"
    )]
    proxy_file: Option<String>,

    #[arg(
        long = "output-dir",
        default_value = ".",
        help = "Specify output directory"
    )]
    output_dir: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    banner::print_simple_banner();

    /*
        let target: String = "en.wikipedia.org".to_string();
        let domain: String = target.clone();
        let domains = ["google.com", "food.com", "en.wikipedia.com"];
        if check_if_save() {
            set_save_file("newfile.txt");
        }
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


        let api_key: String = "XBB0IcjOcI5dAZ1ZwAXSr4U5ChL8HAk8".to_string();
        spyhunt_util::shodan_api(api_key, "spankki.fi".to_string(), false).await;
        spyhunt_util::status_code(target.as_str());
        spyhunt_util::run_cors_misconfig_threads([target.as_str()].to_vec()).await;
        spyhunt_util::run_cors_misconfig_threads(domains.to_vec()).await;
        let x = favicon::init();
        println!("{:#?}", x);
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
        match spyhunt_util::get_favicon_hash("https://www.skype.com/en/".to_string()).await {
            Some(k) => println!("{:#?}", k),
            None => (),
        };
        spyhunt_util::status_code_reqwest(target.as_str()).await;
        spyhunt_util::enumerate_domain("en.wikipedia.org")
            .await
            .unwrap();
        spyhunt_util::enumerate_domain("https://en.wikipedia.org")
            .await
            .unwrap();

        install::install();
    */

    if env::args().count() <= 1 {
        exit(1);
    } else {
        let args = opt::parse();

        match args.save {
            Some(filename) => {
                save_util::set_save_file(&filename);
                save_util::set_save_option(true);
            }
            None => {
                err!("no file name passed");
            }
        }

        match args.nmap {
            Some(ip) => {}
            None => {}
        }

        match args.wordlist {
            Some(filename) => {
                println!("Using wordlist: {}", filename);
            }
            None => {
                err!("No wordlist provided.");
            }
        }

        match args.threads {
            Some(threads) => {
                println!("Threads set to: {}", threads);
            }
            None => {
                println!("Using default threads.");
            }
        }

        match args.scan {
            Some(domain) => {
                println!("Scanning subdomains for: {}", domain);
            }
            None => {
                println!("No domain provided for subdomain scan.");
            }
        }

        match args.tech {
            Some(domain) => {
                println!("Finding technologies on: {}", domain);
            }
            None => {
                println!("No domain provided for technology scan.");
            }
        }

        match args.dns {
            Some(file) => {
                println!("Scanning DNS records from file: {}", file);
            }
            None => {
                println!("No file provided for DNS scan.");
            }
        }

        match args.probe {
            Some(file) => {
                println!("Probing domains in file: {}", file);
            }
            None => {
                println!("No file provided for probing domains.");
            }
        }

        match args.redirects {
            Some(file) => {
                println!("Checking redirects for domains in: {}", file);
            }
            None => {
                println!("No file provided for checking redirects.");
            }
        }

        match args.brokenlinks {
            Some(file) => {
                println!("Searching for broken links in: {}", file);
            }
            None => {
                println!("No file provided for broken links scan.");
            }
        }

        match args.paramspider {
            Some(domain) => {
                println!("Extracting parameters from: {}", domain);
            }
            None => {
                println!("No domain provided for parameter spidering.");
            }
        }

        match args.waybackurls {
            Some(url) => {
                println!("Scanning Wayback URLs for: {}", url);
            }
            None => {
                println!("No URL provided for Wayback scan.");
            }
        }

        match args.javascript {
            Some(domain) => {
                println!("Finding JavaScript files on: {}", domain);
            }
            None => {
                println!("No domain provided for JavaScript scan.");
            }
        }

        match args.webcrawler {
            Some(url) => {
                println!("Crawling URLs and JS files on: {}", url);
            }
            None => {
                println!("No URL provided for web crawling.");
            }
        }

        match args.favicon {
            Some(url) => {
                println!("Getting favicon hash for: {}", url);
            }
            None => {
                println!("No URL provided for favicon hash.");
            }
        }

        match args.faviconmulti {
            Some(url) => {
                println!("Getting favicon hashes (multi) for: {}", url);
            }
            None => {
                println!("No URL provided for favicon multi scan.");
            }
        }

        match args.networkanalyzer {
            Some(url) => {
                println!("Performing network analysis on: {}", url);
            }
            None => {
                println!("No URL provided for network analysis.");
            }
        }

        match args.reverseip {
            Some(ip) => {
                println!("Performing reverse IP lookup for: {}", ip);
            }
            None => {
                println!("No IP provided for reverse lookup.");
            }
        }

        match args.reverseipmulti {
            Some(ip) => {
                println!("Performing reverse IP lookup (multi) for: {}", ip);
            }
            None => {
                println!("No IP provided for reverse multi lookup.");
            }
        }

        match args.statuscode {
            Some(domain) => {
                println!("Getting status code for: {}", domain);
            }
            None => {
                println!("No domain provided for status code.");
            }
        }

        match args.pathhunt {
            Some(file) => {
                println!("Checking directory traversal in: {}", file);
            }
            None => {
                println!("No file provided for directory traversal check.");
            }
        }

        match args.corsmisconfig {
            Some(file) => {
                println!("Checking for CORS misconfiguration in: {}", file);
            }
            None => {
                println!("No file provided for CORS misconfiguration.");
            }
        }

        match args.hostheaderinjection {
            Some(domain) => {
                println!("Performing host header injection on: {}", domain);
            }
            None => {
                println!("No domain provided for host header injection.");
            }
        }

        match args.securityheaders {
            Some(domain) => {
                println!("Scanning security headers for: {}", domain);
            }
            None => {
                println!("No domain provided for security headers scan.");
            }
        }

        match args.enumeratedomain {
            Some(domain) => {
                println!("Enumerating domains for: {}", domain);
            }
            None => {
                println!("No domain provided for enumeration.");
            }
        }

        match args.smuggler {
            Some(domain) => {
                println!("Checking for HTTP smuggling on: {}", domain);
            }
            None => {
                println!("No domain provided for smuggling check.");
            }
        }

        match args.ipaddresses {
            Some(file) => {
                println!("Extracting IPs from file: {}", file);
            }
            None => {
                println!("No file provided for IP extraction.");
            }
        }

        match args.domaininfo {
            Some(file) => {
                println!("Getting domain info from file: {}", file);
            }
            None => {
                println!("No file provided for domain info.");
            }
        }
    }

    Ok(())
}
