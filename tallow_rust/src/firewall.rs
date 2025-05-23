use std::process::Command;
use std::io;
use log::{info, warn, error, debug}; // Added log import

// Helper function to execute a command and check its success.
pub fn execute_command(program: &str, args: &[&str]) -> Result<bool, io::Error> {
    debug!("Executing command: {} {}", program, args.join(" "));
    let output = Command::new(program) // Changed to output() to capture stderr
        .args(args)
        .output()?; 

    if output.status.success() {
        Ok(true)
    } else {
        warn!(
            "Command failed: {} {}. Status: {}. Stderr: {}",
            program,
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(false)
    }
}

pub fn reset_rules(fwcmd_path: &str, ipt_path: &str, has_ipv6: bool) {
    info!("Attempting to reset firewall rules (errors during reset will be logged but ignored)...");

    let fwcmd_bin = format!("{}/firewall-cmd", fwcmd_path.trim_end_matches('/'));
    let ipt_bin = format!("{}/iptables", ipt_path.trim_end_matches('/'));
    let ip6t_bin = format!("{}/ip6tables", ipt_path.trim_end_matches('/'));
    let ipset_bin = format!("{}/ipset", ipt_path.trim_end_matches('/'));

    // Firewalld cleanup commands
    let fw_cleanup_cmds = [
        (fwcmd_bin.as_str(), vec!["--permanent", "--direct", "--remove-rule", "ipv4", "filter", "INPUT", "1", "-m", "set", "--match-set", "tallow", "src", "-j", "DROP"]),
        (fwcmd_bin.as_str(), vec!["--permanent", "--delete-ipset=tallow"]),
    ];
    for (cmd, args_vec) in fw_cleanup_cmds.iter() {
        // Errors from execute_command (I/O errors) are logged by caller if needed.
        // execute_command itself logs command failures (non-zero exit status).
        let _ = execute_command(cmd, &args_vec); // Result is ignored as per subtask for reset
    }
    if has_ipv6 {
        let fw_cleanup_ipv6_cmds = [
            (fwcmd_bin.as_str(), vec!["--permanent", "--direct", "--remove-rule", "ipv6", "filter", "INPUT", "1", "-m", "set", "--match-set", "tallow6", "src", "-j", "DROP"]),
            (fwcmd_bin.as_str(), vec!["--permanent", "--delete-ipset=tallow6"]),
        ];
        for (cmd, args_vec) in fw_cleanup_ipv6_cmds.iter() {
            let _ = execute_command(cmd, &args_vec);
        }
    }

    // iptables cleanup commands
    let ipt_cleanup_cmds = [
        (ipt_bin.as_str(), vec!["-t", "filter", "-D", "INPUT", "-m", "set", "--match-set", "tallow", "src", "-j", "DROP"]),
        (ipset_bin.as_str(), vec!["destroy", "tallow"]),
    ];
     for (cmd, args_vec) in ipt_cleanup_cmds.iter() {
        let _ = execute_command(cmd, &args_vec);
    }
    if has_ipv6 {
        let ipt_cleanup_ipv6_cmds = [
            (ip6t_bin.as_str(), vec!["-t", "filter", "-D", "INPUT", "-m", "set", "--match-set", "tallow6", "src", "-j", "DROP"]),
            (ipset_bin.as_str(), vec!["destroy", "tallow6"]),
        ];
        for (cmd, args_vec) in ipt_cleanup_ipv6_cmds.iter() {
            let _ = execute_command(cmd, &args_vec);
        }
    }
    info!("Firewall rule reset attempt finished.");
}

pub fn setup_firewall(config: &crate::config::Config) -> Result<(), Box<dyn std::error::Error>> {
    if config.nocreate {
        info!("Firewall setup skipped due to 'nocreate' configuration.");
        return Ok(());
    }

    reset_rules(&config.fwcmd_path, &config.ipt_path, config.has_ipv6);

    let fwcmd_bin = format!("{}/firewall-cmd", config.fwcmd_path.trim_end_matches('/'));
    let ipt_bin = format!("{}/iptables", config.ipt_path.trim_end_matches('/'));
    let ip6t_bin = format!("{}/ip6tables", config.ipt_path.trim_end_matches('/'));
    let ipset_bin = format!("{}/ipset", config.ipt_path.trim_end_matches('/'));

    let firewalld_active = match execute_command(&fwcmd_bin, &["--state"]) {
        Ok(status) => status, // true if exit code 0, false otherwise
        Err(_) => false,      // If command fails to run (e.g., not found), assume not active
    };

    if firewalld_active {
        info!("Firewalld detected as active. Setting up rules...");
        let expires_str = config.expires.to_string();
        // Pre-format the string that needs a lifetime
        let timeout_opt_ipv4 = format!("--option=timeout={}", expires_str);
        
        let commands_to_run = [
            (fwcmd_bin.as_str(), vec!["--permanent", "--quiet", "--new-ipset=tallow", "--type=hash:ip", "--family=inet", &timeout_opt_ipv4]),
            (fwcmd_bin.as_str(), vec!["--permanent", "--direct", "--quiet", "--add-rule", "ipv4", "filter", "INPUT", "1", "-m", "set", "--match-set", "tallow", "src", "-j", "DROP"]),
        ];
        for (cmd, args_vec) in commands_to_run.iter() {
            if !execute_command(cmd, args_vec)? {
                return Err(format!("Firewalld command failed: {} {:?}", cmd, args_vec).into());
            }
        }
        if config.has_ipv6 {
            // Pre-format for IPv6 as well
            let timeout_opt_ipv6 = format!("--option=timeout={}", expires_str); // Could reuse expires_str, but this is safer if it were different
            let ipv6_commands_to_run = [
                (fwcmd_bin.as_str(), vec!["--permanent", "--quiet", "--new-ipset=tallow6", "--type=hash:ip", "--family=inet6", &timeout_opt_ipv6]),
                (fwcmd_bin.as_str(), vec!["--permanent", "--direct", "--quiet", "--add-rule", "ipv6", "filter", "INPUT", "1", "-m", "set", "--match-set", "tallow6", "src", "-j", "DROP"]),
            ];
            for (cmd, args_vec) in ipv6_commands_to_run.iter() {
                if !execute_command(cmd, args_vec)? {
                    return Err(format!("Firewalld IPv6 command failed: {} {:?}", cmd, args_vec).into());
                }
            }
        }
        if !execute_command(&fwcmd_bin, &["--reload", "--quiet"])? {
            error!("Firewalld reload command failed");
            return Err("Firewalld reload command failed".into());
        }
        info!("Firewalld rules setup successfully.");

    } else {
        info!("Firewalld not detected or not active. Setting up iptables rules...");
        let expires_str = config.expires.to_string();
        let commands_to_run = [
            // Using -exist for ipset create to avoid error if set already exists (though reset_rules should handle)
            (ipset_bin.as_str(), vec!["-exist", "create", "tallow", "hash:ip", "family", "inet", "timeout", &expires_str]),
            (ipt_bin.as_str(), vec!["-t", "filter", "-A", "INPUT", "-m", "set", "--match-set", "tallow", "src", "-j", "DROP"]),
        ];
        for (cmd, args_vec) in commands_to_run.iter() {
            if !execute_command(cmd, args_vec)? {
                 error!("iptables command failed: {} {:?}", cmd, args_vec);
                return Err(format!("iptables command failed: {} {:?}", cmd, args_vec).into());
            }
        }
        if config.has_ipv6 {
            let ipv6_commands_to_run = [
                (ipset_bin.as_str(), vec!["-exist", "create", "tallow6", "hash:ip", "family", "inet6", "timeout", &expires_str]),
                (ip6t_bin.as_str(), vec!["-t", "filter", "-A", "INPUT", "-m", "set", "--match-set", "tallow6", "src", "-j", "DROP"]),
            ];
            for (cmd, args_vec) in ipv6_commands_to_run.iter() {
                if !execute_command(cmd, args_vec)? {
                    error!("iptables IPv6 command failed: {} {:?}", cmd, args_vec);
                    return Err(format!("iptables IPv6 command failed: {} {:?}", cmd, args_vec).into());
                }
            }
        }
        info!("iptables rules setup successfully.");
    }
    Ok(())
}
