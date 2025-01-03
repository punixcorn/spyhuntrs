#![macro_use]
#![allow(unused_macros)]
/// prints message and exits with 1
macro_rules! err {
    ($msg:expr) => {
        {
            eprintln!("{} {}", "[E]".red(), $msg.bold().red());
            std::process::exit(1);
        }
    };

    ($fmt:expr, $($arg:tt)*) => {
        {
            let formatted_message = format!($fmt, $($arg)*);
            eprintln!("{} {}", "[E]".red().bold(), formatted_message.bold().red());
            std::process::exit(1);
        }
    };
}

/// prints message and continues the process
macro_rules! info {
    ($msg:expr) => {
        {
            println!("{} {}", "[I]".green(), $msg.italic().white());
        }
    };
    ($fmt:expr, $($arg:tt)*) => {
        {
            let formatted_message = format!($fmt, $($arg)*);
            println!("{} {}", "[I]".green().bold(), formatted_message.italic().white());
        }
    };
}

/// prints message and continues the process
macro_rules! warn {
    ($msg:expr) => {
        {
            println!("{} {}", "[W]".yellow().bold(), $msg.italic().yellow())
        }
    };
    ($fmt:expr, $($arg:tt)*) => {
        {
            let formatted_message = format!($fmt, $($arg)*);
            println!("{} {}", "[W]".yellow().bold(), formatted_message.italic().yellow())
        }
    };
}
