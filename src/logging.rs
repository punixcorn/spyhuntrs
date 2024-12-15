#![macro_use]
#![allow(unused_macros)]

macro_rules! err {
    ($message:expr) => {
        println!("[E] {}", $message.bold().red());
        std::process::exit(1);
    };

    ($message:expr,$exit_code:expr) => {
        println!("[E] {}", $message.bold().red());
        if $exit_code > 1 {
            std::process::exit($exit_code);
        }
    };
}

macro_rules! warn {
    ($message:expr) => {
        println!("[W] {}", $message.italic().yellow())
    };

    ($message:expr,$exit_code:expr) => {
        println!("[W] {}", $message.bold().orange());
        if $exit_code > 1 {
            std::process::exit($exit_code);
        }
    };
}

macro_rules! info {
    ($message:expr) => {
        println!("[I] {}", $message.italic().white());
    };
}
