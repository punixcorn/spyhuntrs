#![macro_use]
#![allow(unused_macros)]

use crate::{
    file_util::{file_exists, write_to_file},
    save_file, Save,
};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};

/// checks if the save option was set in args
pub fn check_if_save() -> bool {
    let x = Save.lock().unwrap();
    return x.clone();
}

/// sets the save option state vaule
pub fn set_save_option(value: bool) {
    let mut x = Save.lock().unwrap();
    *x = value;
}

/// returns a string to the save filename
pub fn get_save_file() -> String {
    let x = save_file.lock().unwrap();
    return x.clone();
}

/// change the save filename
/// this will create the file
/// so no need to check if file has been created, just open
pub fn set_save_file(filename: &str) {
    let mut x = save_file.lock().unwrap();
    *x = filename.to_string();

    let mut file: File;
    if !file_exists(&filename) {
        file = File::create(filename).unwrap();
    }
}

pub fn save_vec_strs(buffer: Vec<&str>) {
    let mut file: File;
    let path = &get_save_file();
    file = OpenOptions::new().append(true).open(&path).unwrap();

    for i in buffer {
        writeln!(file, "{}", i).unwrap();
    }
}

pub fn save_vec_strings(buffer: Vec<String>) {
    let mut file: File;
    let path = &get_save_file();
    file = OpenOptions::new().append(true).open(&path).unwrap();

    for i in buffer {
        writeln!(file, "{}", i).unwrap();
    }
}

/// write `buffer` into save_file
pub fn save_string(buffer: String) {
    let mut file: File;
    let path = &get_save_file();
    file = OpenOptions::new().append(true).open(&path).unwrap();
    writeln!(file, "{}", strip_ansi_escapes::strip_str(buffer)).unwrap();
}

///
pub fn save_str(buffer: &str) {
    let mut file: File;
    let path = &get_save_file();
    file = OpenOptions::new().append(true).open(&path).unwrap();
    writeln!(file, "{}", buffer).unwrap();
}

/// this should probably handle logging info out before saving
// macro_rules! handle_data {
//     ($s:expr, &str) => {
//         if save_util::check_if_save() {
//             if save_util::get_save_file().is_empty() {
//                 err!("no save file defined");
//             }
//             save_util::save_str($s)
//         }
//     };
//     ($s:expr,String) => {
//         if save_util::check_if_save() {
//             if save_util::get_save_file().is_empty() {
//                 err!("no save file defined");
//             }
//             save_util::save_string($s)
//         }
//     };
//
//     ($vec: expr,Vec<&str>) => {
//         if save_util::check_if_save() {
//             if save_util::get_save_file().is_empty() {
//                 err!("no save file defined");
//             }
//             save_util::save_vec_strs($vec);
//         }
//     };
//
//     ($vec:expr, Vec<String>) => {
//         if save_util::check_if_save() {
//             if save_util::get_save_file().is_empty() {
//                 err!("no save file defined");
//             }
//             save_util::save_vec_strings($vec);
//         }
//     };
// }

// macro_rules! info_and_handle_data {
//     ($s:expr, &str) => {
//         info!(format!("{}", $s));
//         if save_util::check_if_save() {
//             if save_util::get_save_file().is_empty() {
//                 err!("no save file defined");
//             }
//             save_util::save_str($s)
//         }
//     };
//     ($s:expr,String) => {
//         info!($s);
//         if save_util::check_if_save() {
//             if save_util::get_save_file().is_empty() {
//                 err!("no save file defined");
//             }
//             save_util::save_string($s)
//         }
//     };
//
//     ($vec: expr,Vec<&str>) => {
//         for i in $vec {
//             info!(format!("{i}"));
//         }
//         if save_util::check_if_save() {
//             if save_util::get_save_file().is_empty() {
//                 err!("no save file defined");
//             }
//             save_util::save_vec_strs($vec);
//         }
//     };
//
//     ($vec:expr, Vec<String>) => {
//         for i in $vec {
//             info!(format!("{i}"));
//         }
//         if save_util::check_if_save() {
//             if save_util::get_save_file().is_empty() {
//                 err!("no save file defined");
//             }
//             save_util::save_vec_strings($vec);
//         }
//     };
// }

#[macro_export]
macro_rules! write_info {
    ($s:expr) => {
        if save_util::check_if_save() {
            if save_util::get_save_file().is_empty() {
                err!("no save file defined");
            }
            save_util::save_string(format!("{}",$s))
        }
    };

    ($fmt:expr, $($arg:tt)*) => {
        if save_util::check_if_save() {
            if save_util::get_save_file().is_empty() {
                err!("no save file defined");
            }
            let formatted_message = format!($fmt, $($arg)*);
            save_util::save_string(formatted_message)
        }
    };
}

macro_rules! write_info_and_print_info {
    ($s:expr) => {
        info!($s);
        if save_util::check_if_save() {
            if save_util::get_save_file().is_empty() {
                err!("no save file defined");
            }
            save_util::save_string(format!("{}",$s))
        }
    };

    ($fmt:expr, $($arg:tt)*) => {
        let formatted_message = format!($fmt, $($arg)*);
        info!(formatted_message);
        if save_util::check_if_save() {
            if save_util::get_save_file().is_empty() {
                err!("no save file defined");
            }
            save_util::save_string(formatted_message)
        }
    };
}

macro_rules! write_info_and_print {
    ($s:expr) => {
        println!($s);
        if save_util::check_if_save() {
            if save_util::get_save_file().is_empty() {
                err!("no save file defined");
            }
            save_util::save_string(format!("{}",$s))
        }
    };

    ($fmt:expr, $($arg:tt)*) => {
        let formatted_message = format!($fmt, $($arg)*);
        println!("{}",formatted_message);
        if save_util::check_if_save() {
            if save_util::get_save_file().is_empty() {
                err!("no save file defined");
            }
            save_util::save_string(formatted_message)
        }
    };
}
