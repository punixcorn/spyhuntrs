/// # not available to use , minor issues, might remove
pub mod v1 {
    use crate::user_agents;
    use tokio::time::sleep;
    use tokio::time::Duration;

    use reqwest::{self, blocking::Response, header::HeaderValue, Proxy};
    use scraper::error;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SearchResult {
        pub url: String,
        pub title: String,
        pub description: String,
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
            let desc_selector =
                scraper::Selector::parse("div[style*='-webkit-line-clamp:2']").unwrap();

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
}

/// This version works, but has 2 sub versions because for some reason :
/// when you make a get request with useragent, the returned body is different from no useragent
/// and the request result is better???
/// # subversions
/// - v2::no_user_agent
/// - v2::user_agent
/// # Info
/// They all have the same functions and features, but `v2::user_agent` is better
/// # Example
///  ```rust
///  google_search::v2::user_agent::search("food".to_string(),10).await.unwrap();
///  google_search::v2::no_user_agent::search("food".to_string(),10).await.unwrap();
///  // the structs are the same
///  google_search::v2::GoogleSearchResults == google_search::v1::GoogleSearchResults
///  ```
pub mod v2 {
    /// use no user_agent, the results aren't as good
    /// use `v2::user_agent`
    pub mod no_user_agent {
        use {
            colored::Colorize,
            regex::Regex,
            reqwest::{self, blocking::Client},
            scraper::{self, Element, Html, Selector},
            shodan_client::SearchResult,
        };

        /// data returned from google_search::v2::search(...);
        /// contains url,title,title_url and description
        /// all String
        #[derive(Clone, Debug)]
        pub struct GoogleSearchResult {
            pub url: String,
            pub title: String,
            pub title_url: String,
            pub description: String,
        }

        impl GoogleSearchResult {
            /// fills up with default vaule "Could not retrieve ..."
            fn new() -> Self {
                return Self {
                    url: String::from("Could not retrieve url"),
                    title: String::from("Could not retrieve title"),
                    title_url: String::from("Could not retrieve url title"),
                    description: String::from("Could not retrieve description"),
                };
            }

            /// check if none of the vaules has "could not retrieve"
            pub fn is_fully_populated(&self) -> bool {
                !self.url.contains("Could not retrieve")
                    && !self.title.contains("Could not retrieve")
                    && !self.title_url.contains("Could not retrieve")
                    && !self.description.contains("Could not retrieve")
            }
        }

        /// get any related link about the query
        /// use a huge number of results to get better results eg 50
        /// # Example
        /// ```rust
        /// let s :Vec<String> = google_search::v2::scrape_url("rust language",50).unwrap();
        /// ```
        /// # Panic
        /// will panic if scrape::Selector fails
        pub async fn scrape_url(
            query: String,
            number_of_results: i8,
        ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
            let mut ret: Vec<String> = vec![];

            let body = _req(query, number_of_results).await?.text().await?;

            let document = Html::parse_document(&body);

            // find div with class BNeawe s3v9rd AP7Wnd
            let div_selector = Selector::parse(r#"div.BNeawe.s3v9rd.AP7Wnd"#).unwrap();
            //  find span with class BNeawe inside the div
            let span_selector = Selector::parse(r#"span.BNeawe a"#).unwrap();
            // Regex pattern to clean up the URL
            let re = Regex::new(r"^/url\?q=(.*?)(&|$)").unwrap();

            for div in document.select(&div_selector) {
                if let Some(a_tag) = div.select(&span_selector).next() {
                    if let Some(url) = a_tag.value().attr("href") {
                        if let Some(captured_url) = re.captures(url) {
                            let clean_url = captured_url.get(1).map_or("", |m| m.as_str());
                            ret.push(clean_url.to_string());
                        }
                    }
                }
            }

            Ok(ret)
        }

        /// make a blocking google request with the query and return the Response
        /// # Example
        /// ```rust
        /// let s :reqwest::blocking::Response = google_search::v2::_req("rust language").unwrap();
        /// ```
        /// # Panic
        /// will no panic , will return an error
        pub async fn _req(
            query: String,
            results_num: i8,
        ) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
            let term = query.split(' ').collect::<Vec<_>>().join("+");
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::limited(10))
                .timeout(std::time::Duration::from_secs(5 as u64))
                .build()?;

            let x = client
                .get("https://www.google.com/search")
                .query(&[
                    ("q", term),
                    ("num", results_num.to_string()),
                    ("hl", "en".to_string()),
                ])
                .send()
                .await?;
            Ok(x)
        }

        /// find and return relevant info from google scraping on [query]
        /// use a bigger number in [number_of_results] to get more relevant data eg 50
        /// # Example
        /// ```rust
        /// let x:Vec<google_search::v2::GoogleSearchResult> = google_search::v2::search("rust language",50).unwrap();
        /// ```
        /// # Panic
        /// will panic if regex construction fails
        pub async fn search(
            query: String,
            number_of_results: i8,
        ) -> Result<Vec<GoogleSearchResult>, Box<dyn std::error::Error>> {
            let mut ret: Vec<GoogleSearchResult> = vec![];
            let res = _req(query, number_of_results).await?;
            let response_data = res.text().await?;

            let document = Html::parse_document(&response_data);

            let div_selector = Selector::parse(r#"div.Gx5Zad.xpd"#).unwrap();

            // Regex pattern to clean up the URL
            let re = Regex::new(r"^/url\?q=(.*?)(&|$)").unwrap();

            for element in document.select(&div_selector) {
                let mut search_result: GoogleSearchResult = GoogleSearchResult::new();
                // Extract snippets
                let snippet_selector = Selector::parse(r#"div.BNeawe.s3v9rd.AP7Wnd"#).unwrap();
                if let Some(snippet_element) = element.select(&snippet_selector).next() {
                    let snippet_data = snippet_element.text().collect::<Vec<_>>().join("");
                    search_result.description = snippet_data.clone();
                }

                // Extract the link in header
                let link_header_selector =
                    Selector::parse(r#"div.BNeawe.UPmit.AP7Wnd.lRVwie"#).unwrap();
                if let Some(link_element) = element.select(&link_header_selector).next() {
                    let link_data = link_element.text().collect::<Vec<_>>().join("");
                    search_result.title_url = link_data.clone();
                }

                // Extract header
                let header_selector = Selector::parse(r#"div.BNeawe.vvjwJb.AP7Wnd"#).unwrap();
                if let Some(header_element) = element.select(&header_selector).next() {
                    let header_data = header_element.text().collect::<Vec<_>>().join("");
                    search_result.title = header_data.clone();
                }

                {
                    // LINKPART: this part is for getting actual links
                    let link_div_selector = Selector::parse(r#"div.BNeawe.s3v9rd.AP7Wnd"#).unwrap();
                    let link_selector = Selector::parse(r#"a"#).unwrap();

                    if let Some(div) = element.select(&link_div_selector).next() {
                        if let Some(a_tag) = div.select(&link_selector).next() {
                            if let Some(url) = a_tag.value().attr("href") {
                                if let Some(captured_url) = re.captures(url) {
                                    let clean_url = captured_url.get(1).map_or("", |m| m.as_str());
                                    search_result.url = clean_url.to_string();
                                }
                            }
                        }
                    }
                }
                ret.push(search_result.clone());
            }
            Ok(ret)
        }
    }

    /// This with a useragent, compeletly different results
    /// more of better results but it's different by the code it receives
    pub mod user_agent {
        use {
            reqwest::{self},
            scraper::{self, selectable::Selectable, Html, Selector},
        };

        /// data returned from google_search::v2::search(...);
        /// contains url,title,title_url and description
        /// all String
        #[derive(Clone, Debug)]
        pub struct GoogleSearchResult {
            pub url: String,
            pub title: String,
            pub title_info: String,
            pub description: String,
        }

        impl GoogleSearchResult {
            /// fills up with default vaule "Could not retrieve ..."
            fn new() -> Self {
                return Self {
                    url: String::from("Could not retrieve url"),
                    title: String::from("Could not retrieve title"),
                    title_info: String::from("Could not retrieve url title"),
                    description: String::from("Could not retrieve description"),
                };
            }

            /// check if none of the vaules has "could not retrieve"
            pub fn is_fully_populated(&self) -> bool {
                !self.url.contains("Could not retrieve")
                    && !self.title.contains("Could not retrieve")
                    && !self.title_info.contains("Could not retrieve")
                    && !self.description.contains("Could not retrieve")
            }
        }

        /// get any related link about the query
        /// use a huge number of results to get better results eg 50
        /// # Example
        /// ```rust
        /// let s :Vec<String> = google_search::v2::scrape_url("rust language",50).unwrap();
        /// ```
        /// # Panic
        /// will panic if scrape::Selector fails
        pub async fn scrape_url(
            query: String,
            number_of_results: i8,
        ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
            let mut ret: Vec<String> = vec![];

            let body = _req(query, number_of_results).await?.text().await?;

            let document = Html::parse_document(&body);

            // find div with class BNeawe s3v9rd AP7Wnd
            let div_selector = Selector::parse(r#"div.g.Ww4FFb"#).unwrap();
            //  find span with class BNeawe inside the div

            for element in document.select(&div_selector) {
                // Extract Link
                let link_div_selector = Selector::parse(r#"div.yuRUbf"#).unwrap();
                let link_selector = Selector::parse(r#"a"#).unwrap();

                if let Some(div) = element.select(&link_div_selector).next() {
                    if let Some(a_tag) = div.select(&link_selector).next() {
                        if let Some(url) = a_tag.value().attr("href") {
                            ret.push(url.to_string());
                        }
                    }
                }
            }
            Ok(ret)
        }

        /// make a blocking google request with the query and return the Response
        /// # Example
        /// ```rust
        /// let s :reqwest::blocking::Response = google_search::v2::_req("rust language").unwrap();
        /// ```
        /// # Panic
        /// will no panic , will return an error
        pub async fn _req(
            query: String,
            results_num: i8,
        ) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
            let term = query.split(' ').collect::<Vec<_>>().join("+");
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::limited(10))
                .timeout(std::time::Duration::from_secs(5 as u64))
                .build()?;

            let x = client
            .get("https://www.google.com/search")
            .header(
                reqwest::header::USER_AGENT,
                format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0")
                    .parse::<reqwest::header::HeaderValue>()
                    .unwrap(),
            )
            .query(&[
                ("q", term),
                ("num", results_num.to_string()),
                ("hl", "en".to_string()),
            ])
            .send().await?;
            Ok(x)
        }

        /// find and return relevant info from google scraping on [query]
        /// use a bigger number in [number_of_results] to get more relevant data eg 50
        /// # Example
        /// ```rust
        /// let x:Vec<google_search::v2::GoogleSearchResult> = google_search::v2::search("rust language",50).unwrap();
        /// ```
        /// # Panic
        /// will panic if regex construction fails
        pub async fn search(
            query: String,
            number_of_results: i8,
        ) -> Result<Vec<GoogleSearchResult>, Box<dyn std::error::Error>> {
            let mut ret: Vec<GoogleSearchResult> = vec![];
            let res = _req(query, number_of_results).await?;
            let response_data = res.text().await?;

            let document = Html::parse_document(&response_data);

            let div_selector = Selector::parse(r#"div.g.Ww4FFb"#).unwrap();

            for element in document.select(&div_selector) {
                let mut search_result: GoogleSearchResult = GoogleSearchResult::new();
                // Extract desc
                let desc_div_selector =
                    Selector::parse(r#"div.VwiC3b.yXK7lf.p4wth.r025kc.hJNv6b.Hdw6tb"#).unwrap();
                let span_selector = Selector::parse(r#"span"#).unwrap();

                if let Some(e) = element.select(&desc_div_selector).next() {
                    let mut x = String::new();
                    for span_tag in e.select(&span_selector) {
                        x = span_tag.text().collect::<Vec<_>>().join("");
                    }
                    search_result.description = x.clone();
                }

                // if let Some(div) = element.select(&desc_div_selector).next() {
                //     if let Some(span_tag) = div.select(&span_selector).next() {
                //         let desc = span_tag.text().collect::<Vec<_>>().join("");
                //         search_result.description = desc.clone();
                //     }
                // }

                // Extract the link info in header
                let link_header_selector = Selector::parse(r#"span.VuuXrf"#).unwrap();
                if let Some(link_element) = element.select(&link_header_selector).next() {
                    let link_data = link_element.text().collect::<Vec<_>>().join("");
                    search_result.title_info = link_data.clone();
                }

                // Extract header
                let header_selector = Selector::parse(r#"h3"#).unwrap();
                if let Some(header_element) = element.select(&header_selector).next() {
                    let header_data = header_element.text().collect::<Vec<_>>().join("");
                    search_result.title = header_data.clone();
                }

                // Extract Link
                let link_div_selector = Selector::parse(r#"div.yuRUbf"#).unwrap();
                let link_selector = Selector::parse(r#"a"#).unwrap();

                if let Some(div) = element.select(&link_div_selector).next() {
                    if let Some(a_tag) = div.select(&link_selector).next() {
                        if let Some(url) = a_tag.value().attr("href") {
                            search_result.url = url.to_string();
                        }
                    }
                }
                ret.push(search_result.clone());
            }
            Ok(ret)
        }
    }
}
