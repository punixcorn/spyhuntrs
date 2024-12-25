#![macro_use]
#![allow(unused_macros)]

use crate::{
    file_util::{file_exists, write_to_file},
    save, save_file,
};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};

/// checks if the save option was set in args
pub fn check_if_save() -> bool {
    let x = save.lock().unwrap();
    return x.clone();
}

/// sets the save option state vaule
pub fn set_save_option(value: bool) {
    let mut x = save.lock().unwrap();
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

///
pub fn save_string(buffer: String) {
    let mut file: File;
    let path = &get_save_file();
    file = OpenOptions::new().append(true).open(&path).unwrap();
    writeln!(file, "{}", buffer).unwrap();
}

///
pub fn save_str(buffer: &str) {
    let mut file: File;
    let path = &get_save_file();
    file = OpenOptions::new().append(true).open(&path).unwrap();
    writeln!(file, "{}", buffer).unwrap();
}

/// this should probably handle logging info out before saving
#[macro_export]
macro_rules! handle_data {
    ($s:expr, &str) => {
        if check_if_save() {
            save_util::save_str($s)
        }
    };
    ($s:expr,String) => {
        if check_if_save() {
            save_util::save_string($s)
        }
    };

    ($vec: expr,Vec<&str>) => {
        if check_if_save() {
            save_util::save_vec_strs($vec);
        }
    };

    ($vec:expr, Vec<String>) => {
        if check_if_save() {
            save_util::save_vec_strings($vec);
        }
    };
}

#[macro_export]
macro_rules! info_and_handle_data {
    ($s:expr, &str) => {
        info!(format!("{}", $s));
        if check_if_save() {
            save_util::save_str($s)
        }
    };
    ($s:expr,String) => {
        info!($s);
        if check_if_save() {
            save_util::save_string($s)
        }
    };

    ($vec: expr,Vec<&str>) => {
        for i in $vec {
            info!(format!("{i}"));
        }
        if check_if_save() {
            save_util::save_vec_strs($vec);
        }
    };

    ($vec:expr, Vec<String>) => {
        for i in $vec {
            info!(format!("{i}"));
        }
        if check_if_save() {
            save_util::save_vec_strings($vec);
        }
    };
}

/*
pub struct saveinfo {
    pub file_name: &'static str,
    pub should_save: bool,
}

impl saveinfo {
    pub fn save(&self, data: Vec<String>) -> Result<(), &'static str> {
        if !self.should_save {
            return Ok(());
        }
        if self.file_name.is_empty() {
            return Err("File name is empty");
        }
        let _ = utils::write_to_file(data, self.file_name.to_string().clone());
        Ok(())
    }

    pub fn new(save_file: &'static str, shouldsave: bool) -> Self {
        return Self {
            file_name: save_file,
            should_save: shouldsave,
        };
    }
}
*/
