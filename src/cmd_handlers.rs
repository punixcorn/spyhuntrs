#![allow(unused_macros)]

use colored::Colorize;
use std::path::PathBuf;
use std::process;
use std::process::*;

use crate::logging;

pub struct cmd_info {
    output: Option<String>,
    stderr: Option<String>,
    stdout: Option<String>,
    status: Option<i32>,
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
