#![macro_use]
use crate::user_agents;
use tokio::time::sleep;
use tokio::time::Duration;

use reqwest::{self, blocking::Response, header::HeaderValue, Proxy};
use scraper::error;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearchResult {
    url: String,
    title: String,
    description: String,
}

pub async fn _req(
    term: String,
    results: i32,
    lang: String,
    start: i32,
    proxy: Option<String>,
    timeout: i32,
    safe: String,
    ssl_verify: bool,
    region: String,
) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
    let mut client: reqwest::Client;

    if proxy.is_some() {
        let pxy = Proxy::http(setup_proxy(proxy.unwrap()).unwrap())?;

        client = reqwest::Client::builder()
            .danger_accept_invalid_certs(ssl_verify)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(std::time::Duration::from_secs(timeout as u64))
            .proxy(pxy.clone())
            .build()?;
    }

    client = reqwest::Client::builder()
        .danger_accept_invalid_certs(ssl_verify)
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(std::time::Duration::from_secs(timeout as u64))
        .build()?;

    let response = client
        .get("https://www.google.com/search")
        .header(
            reqwest::header::USER_AGENT,
            user_agents::get_user_agent_prexisting()
                .parse::<HeaderValue>()
                .unwrap(),
        )
        .query(&[
            ("q", term),
            ("num", (results + 2).to_string()),
            ("hl", lang),
            ("start", start.to_string()),
            ("safe", safe),
            ("gl", region),
        ])
        .send()
        .await?;

    return Ok(response);
}

pub async fn search(
    term: String,
    num_results: Option<i32>,
    lang: Option<String>,
    proxy: Option<String>,
    sleep_interval: Option<i32>,
    timeout: Option<i32>,
    safe: Option<String>,
    ssl_verify: Option<bool>,
    region: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut results = Vec::new();
    let mut fetched_results = 0;
    let mut start = 0;

    while fetched_results < num_results.unwrap_or(fetched_results) {
        let resp = _req(
            term.clone(),
            num_results.unwrap() - start,
            lang.clone().unwrap(),
            start,
            proxy.clone(),
            timeout.unwrap_or(1),
            safe.clone().unwrap_or("".to_string()),
            ssl_verify.unwrap_or(false),
            region.clone().unwrap_or("".to_string()),
        )
        .await?;

        let html = resp.text().await?;

        // Create selectors once
        let document = scraper::Html::parse_document(&html);
        let result_selector = scraper::Selector::parse("div.g").unwrap();
        let link_selector = scraper::Selector::parse("a").unwrap();
        let title_selector = scraper::Selector::parse("h3").unwrap();
        let desc_selector = scraper::Selector::parse("div[style*='-webkit-line-clamp:2']").unwrap();

        let mut new_results = 0;

        for element in document.select(&result_selector) {
            // Extract link, title, and description with improved error handling
            let link = match element
                .select(&link_selector)
                .next()
                .and_then(|l| l.value().attr("href"))
                .map(String::from)
            {
                Some(l) if !l.is_empty() => l,
                _ => continue,
            };

            let title = match element
                .select(&title_selector)
                .next()
                .map(|t| t.text().collect::<String>())
            {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };

            let description = match element
                .select(&desc_selector)
                .next()
                .map(|d| d.text().collect::<String>())
            {
                Some(d) if !d.is_empty() => d,
                _ => continue,
            };

            fetched_results += 1;
            new_results += 1;

            let result = SearchResult {
                url: link,
                title,
                description,
            };

            results.push(result.clone());
            println!("{:#?}", result.clone());
            // if advanced {
            // } else {
            //     results.push(SearchResult {
            //         url: result.url,
            //         title: String::new(),
            //         description: String::new(),
            //     });
            // }

            if fetched_results >= num_results.unwrap_or(fetched_results) {
                println!("{:#?}", results);
                return Ok(());
            }
        }

        if new_results == 0 {
            break;
        }

        start += 10;
        sleep(Duration::from_secs(sleep_interval.unwrap_or(1) as u64)).await;
    }
    Ok(())
}
/*
    let mut fetched_results = 0;
    let mut new_results = 0;
    let mut start = 0;

    print!("Starting...\n");
    while fetched_results < num_results.unwrap_or(fetched_results) {
        let resp = _req(
            term.clone(),
            num_results.unwrap_or(10) - start,
            lang.clone().unwrap_or("en".to_string()),
            start,
            proxy.clone(),
            timeout.unwrap_or(5),
            safe.clone().unwrap_or("".to_string()),
            ssl_verify.unwrap_or(false),
            region.clone().unwrap_or("us".to_string()),
        )
        .await?;

        let html = resp.text().await?;
        use scraper::Element;
        use scraper::{Html, Selector};

        // Create selectors
        let document = Html::parse_document(&html);
        let result_selector = Selector::parse("div.g").unwrap();
        let link_selector = scraper::Selector::parse("a").unwrap();
        let title_selector = Selector::parse("h3").unwrap();
        let desc_selector = Selector::parse("div[style*='-webkit-line-clamp:2']").unwrap();

        println!("{:#?}", html);

        // Find all result blocks
        for element in document.select(&result_selector) {
            // Find link
            let link = match element.select(&link_selector).next() {
                Some(l) => l.value().attr("href").unwrap_or("").to_string(),
                None => continue,
            };

            // Skip if link is empty
            if link.is_empty() {
                continue;
            }

            // Find title
            let title = match element.select(&title_selector).next() {
                Some(t) => t.text().collect::<String>(),
                None => continue,
            };

            // Find description
            let description = match element.select(&desc_selector).next() {
                Some(d) => d.text().collect::<String>(),
                None => continue,
            };

            // Skip if we're missing any required elements
            if title.is_empty() || description.is_empty() {
                continue;
            }

            fetched_results += 1;
            new_results += 1;
            println!("{:#?}\n{:#?}\n{:#?}", description, title, link);
            if fetched_results >= num_results.unwrap() {}
        }

        // Break if no new results were found
        if new_results == 0 {
            //Uncomment to print warning about insufficient results
            // eprintln!(
            //     "Only {} results found for query requiring {} results. Moving on to the next query.",
            //     fetched_results, num_results
            // );
            break;
        }

        sleep(core::time::Duration::from_secs(
            sleep_interval.unwrap() as u64
        ))
        .await;
    }

    Ok(())
}
*/

/// you can either pass in a [proxy] or a [proxy file name] as the [proxy]
/// but you need to specify if its a proxy_file using the boolean [is_proxy_file]
/// need fix [completed]
/// # example
/// ```rust
/// let x : String = setup_proxies("http://127.0.0.1:8095",false).unwrap;
/// ```
pub fn setup_proxy(mut proxy: String) -> Option<String> {
    let mut ret_proxy: Vec<String> = vec![];

    if proxy.is_empty() {
        return None;
    }

    let protocols = vec!["http://", "https://", "socks4://", "socks5://"];

    for __protocol in &protocols {
        if proxy.starts_with(__protocol) {
            return Some(proxy);
            break;
        }
    }
    return Some(format!("http://{proxy}"));
}

#[macro_export]
macro_rules! google_search {
    ($query:expr) => {
        google_search::search(
            $query,
            Some(3),
            Some("en".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
    };
}
