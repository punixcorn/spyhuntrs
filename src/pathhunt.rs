#![allow(dead_code)]
use std::error::Error;
use std::str::FromStr;

use crate::file_util;
use crate::handle_deps;
use crate::request::{self, urljoin};
use crate::user_agents::{self, get_user_agent};
use colored::Colorize;
use futures::future;
use futures::SinkExt;
use regex::Regex;
use reqwest::header;
use std::path::*;

pub async fn get_path_traversal_list() -> Vec<String> {
    let mut ret: Vec<String> = Vec::new();
    let deps_path = handle_deps::check_or_clone_spyhuntrs_deps();
    let path = format!("{deps_path}/payloads/traversal.txt");
    if file_util::file_exists(&path) {
        ret = file_util::read_from_file(path).unwrap();
    } else {
        warn!(format!(
            "spyhuntrs-deps is needed:\n RUN:{}",
            "git clone https://github.com/punixcorn/spyhuntrs-deps ~/.spyhuntrs-deps".green()
        ));
        std::process::exit(1);
    }
    return ret;
}

pub async fn scan_target(target: String) -> Option<()> {
    let user_agent = get_user_agent(false, false).await.to_string();
    let mut vulnerable: Vec<String> = vec![];

    let client = reqwest::Client::builder().build().unwrap();
    for path in get_path_traversal_list().await {
        let link = format!("{target}{path}");
        let response = client
            .get(link)
            .header(header::USER_AGENT, user_agent.clone())
            .send()
            .await;

        let resp = match response {
            Ok(resp) => resp,
            _ => continue,
        };

        if resp.status().is_success() {
            let data = resp.text().await;
            match data {
                Ok(info) => {
                    if info.contains("root:x:") {
                        vulnerable.push(format!("{target}{path}"));
                    }
                }
                _ => continue,
            };
        }
    }
    // -imp save
    if vulnerable.len() != 0 {
        warn!("Path Traversal");
        for i in &vulnerable {
            println!("[+] {i}");
        }
    }
    Some(())
}

pub async fn scan_target_tokio(targets: Vec<String>) {
    let tasks = targets.into_iter().map(|domain| {
        tokio::spawn(async move {
            scan_target(domain).await;
        })
    });
    future::join_all(tasks).await;
}

pub async fn scan_params_tokio(targets: Vec<String>) {
    let tasks = targets.into_iter().map(|domain| {
        tokio::spawn(async move {
            scan_params(domain).await;
        })
    });
    future::join_all(tasks).await;
}

pub async fn scan_params(target: String) -> Option<()> {
    let client = reqwest::Client::builder().build().unwrap();
    let user_agent = user_agents::get_user_agent(false, false).await;
    let response = client
        .get(target.clone())
        .header(header::USER_AGENT, user_agent.clone())
        .send()
        .await;

    let content = match response {
        Ok(data) => data.text().await.unwrap_or_else(|_| String::from("")),
        _ => String::from(""),
    };

    if content.len() == 0 {
        return None;
    }

    let href_regex = Regex::new("(?i)href=\"(.*?)\"").unwrap();
    let src_regex = Regex::new("(?i)src=\"(.*?)\"").unwrap();

    let href_links: Vec<&str> = href_regex
        .captures_iter(&content)
        .map(|cap| cap.get(1).unwrap().as_str())
        .collect();

    let src_links: Vec<&str> = src_regex
        .captures_iter(&content)
        .map(|cap| cap.get(1).unwrap().as_str())
        .collect();

    // println!("href links: {:?}", href_links);
    // println!("src links: {:?}", src_links);

    // remove dups
    // this holds a non dup of the original vector
    let mut duplicate_full_links: Vec<&str> = vec![];

    for i in src_links.clone() {
        if href_links.contains(&i) {
            continue;
        }
        duplicate_full_links.push(i);
    }

    for i in href_links.clone() {
        duplicate_full_links.push(i);
    }

    // println!("dup : {:?}", duplicate_full_links);

    // holds all the links that can be paramed, eg domain.com/foo=2
    let mut param_links: Vec<String> = vec![];

    for link in href_links.clone() {
        let l: String = urljoin(target.to_string(), link.to_string());
        if duplicate_full_links.contains(&l.as_str()) {
            if l.contains("=") {
                param_links.push(l);
            }
        }
    }

    for link in src_links.clone() {
        let l: String = urljoin(target.to_string(), link.to_string());
        if duplicate_full_links.contains(&l.as_str()) {
            if l.contains("=") {
                param_links.push(l);
            }
        }
    }

    // get  all the paramed links, eg domain.com/foo=
    let mut vulnerable: Vec<String> = vec![];
    let mut parameters_list: Vec<String> = vec![];

    info!("Param links");
    for i in &param_links {
        println!("{i}");
    }

    for param in &param_links {
        let param_vec: Vec<&str> = param.split('=').collect();
        let trip_first_time = false;
        for p in &duplicate_full_links {
            if p.ends_with("=") {
                parameters_list.push(p.to_string());
            }
        }
    }

    // -imp save
    info!("Parameters found");
    for i in &parameters_list {
        println!(" |-{i}");
    }
    println!(" *");

    // -imp save
    info!("Full links found");
    for i in &duplicate_full_links {
        println!(" |-{i}");
    }
    println!(" *");

    let path_traversal_list = get_path_traversal_list().await;

    for parameter in &parameters_list {
        for path in &path_traversal_list {
            let ug = user_agents::get_user_agent(false, false).await;
            let current_url = urljoin(parameter.to_string(), path.to_string());
            let resp = client
                .get(&current_url)
                .header(header::USER_AGENT, user_agent.clone())
                .send()
                .await;
            let body = match resp {
                Ok(data) => data,
                _ => continue,
            };

            if body.status().is_success() {
                let content = match body.text().await {
                    Ok(data) => {
                        if data.contains("root:x:") {
                            vulnerable.push(current_url);
                        }
                    }
                    _ => continue,
                };
            };
        }
    }

    // -imp save
    if vulnerable.len() != 0 {
        warn!("Path Traversal:");
        for i in &vulnerable {
            println!("{i}");
        }
    }

    Some(())
}
