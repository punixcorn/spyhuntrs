#![allow(unused_macros)]

use colored::Colorize;
use std::path::PathBuf;
use std::process;
use std::process::*;

use crate::{logging, save};

pub struct cmd_info {
    pub output: Option<String>,
    pub stderr: Option<String>,
    pub stdout: Option<String>,
    pub status: Option<i32>,
}

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

pub fn run_piped(mut cmd1: Vec<&str>, mut cmd2: Vec<&str>) -> Option<()> {
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
        .expect(stringify!("Failed to start {}", cmd1_bin));

    let mut cmd2_proc = Command::new(cmd2_bin)
        .args(cmd2)
        .stdin(cmd1_proc.stdout.unwrap())
        .spawn()
        .expect(stringify!("Failed to start {}", cmd2_bin));

    let _ = cmd2_proc.wait().expect("Failed to wait on process");

    return Some(());
}
