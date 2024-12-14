#![macro_use]
#![allow(unused_macros)]

use crate::user_agents::{self, get_user_agent};
use reqwest::{header, Response};
use std::error::Error;
use std::path::*;

macro_rules! get {
    ($url : expr ) => {
        let ret = fetch(url, "".to_string()).unwrap();
        return ret;
    };
}

pub async fn fetch(url: String, useragent: String) -> Result<Response, String> {
    let mut user_agent: String = useragent;
    if user_agent.len() == 0 {
        user_agent = get_user_agent(false, false).await.to_string();
    }
    let client = reqwest::Client::builder().build().unwrap();
    let response = client
        .get(&url)
        .header(header::USER_AGENT, user_agent.clone())
        .send()
        .await;
    match response {
        Ok(Response) => Ok(Response),
        _ => Err("Failed to get response".to_string()),
    }
}

/// joins a domain and path eg www.domain.com/ + /api/v1  -> www.domain.com/api/v1
/// domain.com/?foo= + /api/vi = domain.com/?foo=/ap/vi
pub fn urljoin(url: String, path: String) -> String {
    let mut ret: String = String::new();
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
