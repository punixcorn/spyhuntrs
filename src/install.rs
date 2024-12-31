use std::collections::HashMap;
use std::process::{Command, Output};
use std::{env, fs};

pub fn run_command(cmd: &str) -> Option<String> {
    println!("Running command: {}", cmd);
    let output = Command::new("sh").arg("-c").arg(cmd).output();

    match output {
        Ok(Output {
            stdout,
            stderr,
            status,
            ..
        }) if status.success() => {
            let result = String::from_utf8_lossy(&stdout).to_string();
            println!("Command output: {}", result.trim());
            Some(result)
        }
        Ok(Output { stderr, .. }) => {
            println!("Command failed: {}", String::from_utf8_lossy(&stderr));
            None
        }
        Err(e) => {
            println!("Error running command: {}", e);
            None
        }
    }
}

pub fn detect_package_manager() -> Option<String> {
    let managers = vec!["apt", "dnf", "yum", "pacman", "zypper", "apk", "brew"];
    for manager in &managers {
        if Command::new("which").arg(manager).output().is_ok() {
            return Some(manager.to_string());
        }
    }
    None
}

pub fn install_package(package: &str, manager: &str) {
    let cmd = match manager {
        "apt" => format!("sudo apt install -y {}", package),
        "dnf" | "yum" => format!("sudo {} install -y {}", manager, package),
        "pacman" => format!("sudo pacman -S --noconfirm {}", package),
        "zypper" => format!("sudo zypper install -y {}", package),
        "apk" => format!("sudo apk add {}", package),
        "brew" => format!("brew install {}", package),
        "pip" => format!("pip install --break-system-packages {}", package),
        "npm" => format!("sudo npm install -g {}", package),
        _ => {
            println!("Unsupported package manager: {}", manager);
            return;
        }
    };
    run_command(&cmd);
}

pub fn install_go_tool(tool: &str, go_package: &str) {
    println!("Installing Go tool: {}", tool);
    if let Some(_) = run_command(&format!("go install {}", go_package)) {
        let go_path = run_command("go env GOPATH").unwrap_or_else(|| "/usr/local/go".to_string());
        let bin_path = format!("{}/bin/{}", go_path.trim(), tool);
        if fs::metadata(&bin_path).is_ok() {
            run_command(&format!("sudo mv {} /usr/local/bin/", bin_path));
            println!("{} installed successfully.", tool);
        } else {
            println!("Failed to find binary for {}", tool);
        }
    } else {
        println!("Failed to install Go tool: {}", tool);
    }
}

pub fn update_upgrade_system(manager: &str) {
    println!("Updating and upgrading the system...");
    let cmd = match manager {
        "apt" => "sudo apt update && sudo apt upgrade -y",
        "dnf" | "yum" => &format!("sudo {} update -y", manager),
        "pacman" => "sudo pacman -Syu --noconfirm",
        "zypper" => "sudo zypper update -y",
        "apk" => "sudo apk update && sudo apk upgrade",
        _ => {
            println!("Unsupported package manager: {}", manager);
            return;
        }
    };
    run_command(cmd);
}

fn which(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map_or(false, |o| o.status.success())
}

pub fn ensure_pip_installed(package_manager: &str) {
    if !which("pip3") && !which("pip") {
        println!("pip is not installed. Installing pip...");
        let system = std::env::consts::OS;
        match system {
            "linux" => match package_manager {
                "apt" => run_command("sudo apt install -y python3-pip"),
                "dnf" | "yum" => {
                    run_command(&format!("sudo {} install -y python3-pip", package_manager))
                }
                "pacman" => run_command("sudo pacman -S --noconfirm python-pip"),
                "zypper" => run_command("sudo zypper install -y python3-pip"),
                "apk" => run_command("sudo apk add py3-pip"),
                _ => {
                    eprintln!("Unsupported package manager: {}", package_manager);
                    None
                }
            },
            "darwin" => run_command("brew install python"), // This will install pip as well
            _ => {
                eprintln!("Unsupported system: {}", system);
                None
            }
        };
        println!("pip installed successfully");
    } else {
        println!("pip is already installed");
    }
}

pub fn install() {
    let system = env::consts::OS;
    println!("Detected system: {}", system);

    let package_manager = detect_package_manager();
    if package_manager.is_none() {
        println!("Could not detect a supported package manager.");
        return;
    }
    let manager = package_manager.unwrap();
    println!("Detected package manager: {}", manager);

    update_upgrade_system(&manager);

    let tools = vec![
        (
            "subfinder",
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        ),
        ("waybackurls", "github.com/tomnomnom/waybackurls@latest"),
        ("httprobe", "github.com/tomnomnom/httprobe@latest"),
        (
            "httpx",
            "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        ),
        ("anew", "github.com/tomnomnom/anew@latest"),
        ("gau", "github.com/lc/gau/v2/cmd/gau@latest"),
        ("gauplus", "github.com/bp0lr/gauplus@latest"),
        ("hakrawler", "github.com/hakluke/hakrawler@latest"),
        ("assetfinder", "github.com/tomnomnom/assetfinder@latest"),
        (
            "asnmap",
            "github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
        ),
        (
            "naabu",
            "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        ),
    ];

    for (tool, go_package) in tools {
        install_go_tool(tool, go_package);
    }

    let packages = vec!["nodejs", "npm", "python3-pip", "go", "jq"];
    for package in packages {
        install_package(package, &manager);
    }

    install_package("shodan", "pip");
    install_package("broken-link-check", "npm");

    println!("Installing paramSpider");
    run_command("git clone https://github.com/devanshbatham/paramspider && cd paramspider && python3 setup.py install");

    println!("All tools installed successfully!");
}
