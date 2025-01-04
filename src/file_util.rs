#![allow(unused)]

use colored::Colorize;
use reqwest::get;
use reqwest::{Body, Response, StatusCode};
use soup::Soup;
use soup::{self, NodeExt, QueryBuilderExt};
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

/// checks if a file exists
pub fn file_exists<T>(filePath: &T) -> bool
where
    T: std::convert::AsRef<std::ffi::OsStr>,
{
    return Path::new(filePath).exists();
}
/// reads lines from a file and returns a `Vec<String>`
///
/// # Example
/// ```rust
///     let x :Vec<String> = file_util::read_from_file("./foo.txt".to_string()).unwrap();
///     for i in x {
///         println("{i}");
///     }
///     
/// ```
pub fn read_from_file(path: String) -> std::io::Result<Vec<String>> {
    // Open the file
    let file = File::open(path)?;

    // Create a buffered reader
    let reader = BufReader::new(file);

    // Read the file line by line and collect them into a Vec<String>
    let lines: Vec<String> = reader
        .lines()
        .collect::<Result<Vec<String>, std::io::Error>>()?; // Collecting lines into Vec<String>

    Ok(lines)
}

/// write lines to a file ( truncates by default )
/// # Example
/// ```rust
/// let buffer = ["line 1".to_string(), "line 2".to_string()].to_vec();
/// let x = file_util::write_to_file(buffer,"./foo.txt".to_string()).unwrap();
/// assert_eq!(x,());
/// ```
pub fn write_to_file(buffer: Vec<String>, path: String) -> std::io::Result<()> {
    let mut file: File;
    // create truncates if it exists ( stupid )
    file = File::create(path)?;

    for i in buffer {
        writeln!(file, "{}", i)?;
    }

    return Ok(());
}
