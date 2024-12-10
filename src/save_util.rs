#![macro_use]
#![allow(unused_macros)]

use crate::utils;

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
