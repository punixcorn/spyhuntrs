#![allow(unused)]

use core::panic;
use regex::Regex;

use std::process::Output;

use crate::{
    request::{self, urljoin},
    user_agents::{self, get_user_agent, get_user_agent_prexisting},
};
use colored::Colorize;
use reqwest::header;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
struct ArchivedSnapshots {
    closest: Closest,
}

#[derive(Deserialize, Serialize, Debug)]
struct Closest {
    status: String,
    available: bool,
    url: String,
    timestamp: String,
}

#[derive(Deserialize, Debug)]
struct ApiResponse {
    url: String,
    archived_snapshots: ArchivedSnapshots,
}

pub async fn get_wayback_snapshot(url: String) -> Option<String> {
    let new_url = request::urljoin(
        "http://archive.org/wayback/available?url=".to_string(),
        url.clone(),
    );

    let response = reqwest::get(new_url)
        .await
        .unwrap()
        .json::<ApiResponse>()
        .await;

    //    println!("{:?}", response);
    match response {
        Ok(json_resp) => Some(json_resp.url),
        Err(_) => None,
    }
}

/// ignore this stupid function
pub async fn waybackmachine_scan(target: String) -> Option<()> {
    let wayback_link = get_wayback_snapshot(target).await.unwrap();

    let resp = request::fetch(wayback_link.clone(), "".to_string())
        .await
        .unwrap();

    let href_regex = Regex::new("(?i)href=\"(.*?)\"").unwrap();

    let mut all_links: Vec<String> = vec![];
    if resp.status().is_success() {
        let content = resp.text().await.unwrap();

        let href_links: Vec<&str> = href_regex
            .captures_iter(&content)
            .map(|cap| cap.get(1).unwrap().as_str())
            .collect();

        for link in &href_links {
            all_links.push(urljoin(wayback_link.clone(), link.to_string()));
        }
    }

    for i in all_links {
        println!("{}", i);
    }
    Some(())
}
