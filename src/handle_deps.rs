use colored::Colorize;
use std::env;
use std::fmt::format;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn check_or_clone_spyhuntrs_deps() -> String {
    // Define paths
    let home_dir = env::var("HOME").expect("Unable to fetch the home directory.");
    let hidden_path = format!("{}/.spyhuntrs-deps/payloads", home_dir);
    let visible_path = format!("{}/spyhuntrs-deps/payloads", home_dir);
    let repo_url = "https://github.com/punixcorn/spyhuntrs-deps";
    let clone_path = format!("{}/.spyhuntrs-deps", home_dir);

    // Check if either path exists
    if Path::new(&hidden_path).exists() {
        return format!("{home_dir}/.spyhuntrs-deps");
    } else if Path::new(&visible_path).exists() {
        return format!("{home_dir}/spyhuntrs-deps");
    }

    // Clone the repo if neither path exists
    info!(format!(
        "Neither path exists. Cloning the repository to `{}`...",
        clone_path
    ));
    let clone_result = Command::new("git")
        .arg("clone")
        .arg(repo_url)
        .arg(&clone_path)
        .output();

    // Check for errors during cloning
    match clone_result {
        Ok(output) if output.status.success() => {
            info!("Repository successfully cloned.");
            return format!("{home_dir}/.spyhuntrs-deps");
        }
        Ok(output) => {
            warn!(format!(
                "Failed to clone repository. Git output: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Err(e) => {
            warn!(format!("Error while running git: {}", e));
        }
    }

    // Exit with error message
    err!(format!(
        "Can't find spyhuntrs-deps in home folder. Please manually clone: {}",
        repo_url
    ));
    std::process::exit(1);
}
