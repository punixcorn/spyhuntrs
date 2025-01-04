use colored::Colorize;

/// Print a The banner, nothing fancy
/// # Example
/// ```rust
///    let x =  print_simple_banner();
///    assert_eq!(x,());
/// ```
pub fn print_simple_banner() {
    println!("{} @ punixcorn v0.0.2-alpha\n", "spyhuntrs".yellow());
}

/// Print a The fancy banner in spyhunt
/// # Example
/// ```rust
///    let x =  print_simple_banner();
///    assert_eq!(x,());
/// ```
pub fn print_banner() {
    let banner = r#"
  ██████  ██▓███ ▓██   ██▓ ██░ ██  █    ██  ███▄    █ ▄▄▄█████▓ ██▀███    ██████ 
▒██    ▒ ▓██░  ██▒▒██  ██▒▓██░ ██▒ ██  ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒▓██ ▒ ██▒▒██    ▒ 
░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░▒██▀▀██░▓██  ▒██░▓██  ▀█ ██▒▒ ▓██░ ▒░▓██ ░▄█ ▒░ ▓██▄   
  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░░▓█ ░██ ▓▓█  ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ ▒██▀▀█▄    ▒   ██▒
▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░░▓█▒░██▓▒▒█████▓ ▒██░   ▓██░  ▒██▒ ░ ░██▓ ▒██▒▒██████▒▒
▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒  ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒   ▒ ░░   ░ ▒▓ ░▒▓░▒ ▒▓▒ ▒ ░
░ ░▒  ░ ░░▒ ░     ▓██ ░▒░  ▒ ░▒░ ░░░▒░ ░ ░ ░ ░░   ░ ▒░    ░      ░▒ ░ ▒░░ ░▒  ░ ░
░  ░  ░  ░░       ▒ ▒ ░░   ░  ░░ ░ ░░░ ░ ░    ░   ░ ░   ░        ░░   ░ ░  ░  ░  
      ░           ░ ░      ░  ░  ░   ░              ░             ░           ░  
                  ░ ░                                                            
"#;

    println!("{}\n@ punixcorn v0.0.2-alpha\n", banner.yellow());
}
