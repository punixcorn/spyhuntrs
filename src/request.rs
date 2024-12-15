#![macro_use]
use crate::user_agents::{self, get_user_agent};
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
    let mut ret: String = String::new();

    if !url.starts_with("https://") && !url.starts_with("http://") {
        url.insert_str(0, "https://");
    }

    if path.len() == 0 {
        return url;
    }

    if url.ends_with("=") {
        return format!("{url}{path}");
    }

    if url.ends_with("/") {
        if path.starts_with("/") {
            return format!("{}{}", url, path.clone().remove(0));
        }
        return format!("{url}{path}");
    }

    if path.starts_with("/") {
        return format!("{url}{path}",);
    }

    return format!("{url}/{path}");
    // could have just removed the '/' from each, but string cloning
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
