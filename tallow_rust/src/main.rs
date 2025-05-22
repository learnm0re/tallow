mod config;

fn main() {
    match config::load_config("config.toml") {
        Ok(cfg) => {
            println!("Loaded config: {:?}", cfg);
        }
        Err(e) => {
            eprintln!("Error loading config: {}", e);
            // Fallback to default config if loading fails
            let default_cfg = config::Config {
                ipt_path: "/usr/sbin".to_string(),
                fwcmd_path: "/usr/sbin".to_string(),
                expires: 3600,
                whitelist: vec!["127.0.0.1".to_string(), "::1".to_string()],
                has_ipv6: true,
                nocreate: false,
            };
            println!("Using default config: {:?}", default_cfg);
        }
    }
}
