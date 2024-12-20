#![macro_use]
#![allow(unused_macros)]

/// prints message and exits with 1
macro_rules! err {
    ($message:expr) => {
        println!("{} {}", "[E]".red(), $message.bold().red());
        std::process::exit(1);
    };

    ($message:expr,$exit_code:expr) => {
        println!("{} {}", "[E]".red(), $message.bold());
        if $exit_code > 1 {
            std::process::exit($exit_code);
        }
    };
}

/// prints message and continues the process
macro_rules! warn {
    ($message:expr) => {
        println!("{} {}", "[W]".yellow().bold(), $message.italic().yellow())
    };
    ($message:expr,$exit_code:expr) => {
        println!("{} {}", "[W]".yellow().bold(), $message.bold().orange());
        if $exit_code > 1 {
            std::process::exit($exit_code);
        }
    };
}

/// prints message and continues the process
macro_rules! info {
    ($message:expr) => {
        println!("{} {}", "[I]".green(), $message.italic().white());
    };
}
