#![allow(unused_macros)]

use colored::Colorize;
use core::str;
use std::os::unix::process::ExitStatusExt;
use std::process;
use std::process::*;
use std::{io::Read, path::PathBuf};

use crate::{logging, save};

/// stderr,stdout are strings
/// status is the status code
/// output is the orginal output of the process
pub struct cmd_info {
    pub stderr: Option<String>,
    pub stdout: Option<String>,
    pub status: Option<i32>,
    pub output: Option<std::process::Output>,
}

/// split the string into Vec<&str> and passed into run_cmd(...) to run
pub fn run_cmd_string(mut cmd: String) -> Option<cmd_info> {
    let cmd_vec: Vec<_> = cmd.split(' ').collect();
    match run_cmd(cmd_vec) {
        Some(data) => Some(data),
        _ => None,
    }
}

/// takes a vector of strings of the full command and runs it
/// eg run_cmd([["ls","-al"]].to_vec);
pub fn run_cmd(mut args: Vec<&str>) -> Option<cmd_info> {
    if args.len() == 0 {
        return None;
    }

    let mut cmd_result: cmd_info = cmd_info {
        output: None,
        stderr: None,
        stdout: None,
        status: None,
    };

    let mut cmd = process::Command::new(args[0]);
    args.remove(0);

    match cmd.args(args).output() {
        Ok(output) => {
            cmd_result.output = Some(output.clone());
            if output.status.code().unwrap() == 0 || output.status.success() {
                cmd_result.stdout = Some(String::from_utf8(output.stdout).unwrap());
                cmd_result.status = Some(0);
            } else {
                cmd_result.stderr = Some(String::from_utf8(output.stderr).unwrap());
                cmd_result.status = Some(output.status.code().unwrap());
            }
            Some(cmd_result)
        }
        _ => None,
    }
}

/// runs cmd1 | cmd2
/// eg: run_piped_strings("ls","grep hello");
/// the strings are broken into Vec<&str> and passed into run_piped(...)
pub fn run_piped_strings(mut cmd1: String, mut cmd2: String) -> Option<cmd_info> {
    let cmd1_as_vec: Vec<_> = cmd1.split(' ').collect();
    let cmd2_as_vec: Vec<_> = cmd2.split(' ').collect();
    match run_piped(cmd1_as_vec, cmd2_as_vec) {
        Some(ci) => Some(ci),
        _ => None,
    }
}

/// runs cmd1 | cmd2
/// eg run_piped(["ls"].to_vec(),["grep","hello"].to_vec());
/// cmd1 output is piped into cmd2
pub fn run_piped(mut cmd1: Vec<&str>, mut cmd2: Vec<&str>) -> Option<cmd_info> {
    if cmd1.len() == 0 || cmd2.len() == 0 {
        return None;
    }

    let cmd1_bin = cmd1[0];
    let cmd2_bin = cmd2[0];

    cmd1.remove(0);
    cmd2.remove(0);

    let cmd1_proc = Command::new(cmd1_bin)
        .args(cmd1)
        .stdout(Stdio::piped())
        .spawn()
        .expect(format!("Failed to start {}", cmd1_bin).as_str());

    let mut cmd2_proc = Command::new(cmd2_bin)
        .args(cmd2)
        .stdin(cmd1_proc.stdout.unwrap_or_else(|| {
            warn!("run piped: cmd1 stdout failed");
            panic!();
        }))
        .output();

    let mut _x = match cmd2_proc {
        Ok(ok) => ok,
        Err(err) => panic!(
            "error occured during running command: {}\n{}",
            cmd2_bin,
            err.to_string()
        ),
    };

    //println!("{:#?}", _x);

    let mut cmd_result: cmd_info = cmd_info {
        output: Some(_x.clone()),
        stderr: Some(String::from_utf8(_x.stderr).unwrap_or_else(|_| String::from(""))),
        stdout: Some(String::from_utf8(_x.stdout).unwrap_or_else(|_| String::from(""))),
        status: Some(_x.status.signal().unwrap_or_else(|| 1)),
    };

    // let mut outputdata: String = String::new();
    // let x = cmd2_proc
    //     .stdout
    //     .take()
    //     .unwrap()
    //     .read_to_string(&mut outputdata);
    // match {
    //
    // }
    return Some(cmd_result);
}
