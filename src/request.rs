#![macro_use]
use crate::user_agents::{self, get_user_agent};
use colored::Colorize;
use reqwest::{header, Response};
use std::error::Error;
use std::path::Path;

/// fetch a url, with a useragent
/// useragent can be empty and usually should be
/// use fetch_url!(...) for easier handling
pub async fn fetch(url: String, mut user_agent: String) -> Result<Response, String> {
    if user_agent.len() == 0 {
        user_agent = get_user_agent(false, false).await.to_string();
    }

    let client = reqwest::Client::builder().build().unwrap();
    let response = client
        .get(urljoin(url, "".to_string()))
        .header(header::USER_AGENT, user_agent.clone())
        .send()
        .await;
    match response {
        Ok(res) => Ok(res),
        Err(err) => Err(format!("Failed to get response: {}", err).to_string()),
    }
}

/// joins a domain and path eg www.domain.com/ + /api/v1  -> www.domain.com/api/v1
/// domain.com/?foo= + /api/vi = domain.com/?foo=/ap/vi
pub fn urljoin(mut url: String, path: String) -> String {
    let parse_url = reqwest::Url::parse(&url);

    // this checks for all scheme, instead of eariler just https/http
    // i could split it by the ://
    // but i would need a map of all scheme to check
    // and i hope reqwest has a map it checks by

    match parse_url {
        Ok(_url) => {
            if _url.scheme().is_empty() {
                url.insert_str(0, "https://");
            }
        }
        Err(_) => {
            if !url.starts_with("https://") && !url.starts_with("http://") {
                url.insert_str(0, "https://");
            }
        }
    }

    if path.is_empty() {
        return url;
    }

    // i would remove this and replace with reqwest::set_query / reqwest::set_path
    // but checking if its a path or query is not something i want to do now
    // Later

    if url.ends_with("/") {
        // If the path starts with a '/', just append it without adding another '/'
        if path.starts_with("/") {
            return format!("{}{}", url, &path[1..]); // Skip the leading slash of the path
        }
        return format!("{}{}", url, path); // Directly append the path
    }

    if path.starts_with("/") {
        return format!("{}{}", url, path); // Simply append the path
    }

    return format!("{}/{}", url, path);
}

/// fetches a domain with default values
/// unwraps , so if there's any error it will panic
#[macro_export]
macro_rules! fetch_url_unwrap {
    ($url : expr ) => {
        request::fetch(request::urljoin($url, "".to_string()), "".to_string())
            .await
            .unwrap()
    };
}

/// fetches a domain with default values
/// does not unwrap
#[macro_export]
macro_rules! fetch_url {
    ($url : expr ) => {
        request::fetch(request::urljoin($url, "".to_string()), "".to_string()).await
    };
}

#[macro_export]
macro_rules! validate_url {
    ($url :expr ) => {
        request::urljoin(format!("{}", $url), "".to_string())
    };
}
