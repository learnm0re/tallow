mod config;
mod journal;
mod patterns;
mod tracking;
mod firewall;

use log::{info, warn, error, debug, trace}; // Added log import
use systemd::journal::JournalWaitResult;
use std::time::{Duration, UNIX_EPOCH};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;

fn main() {
    // Initialize env_logger
    env_logger::init();
    info!("Tallow-rust starting up...");

    // Setup signal handling for graceful termination and SIGUSR1 state dump
    let term_now = Arc::new(AtomicBool::new(false));
    let sig_term_now = Arc::clone(&term_now); // Clone for the signal handler thread

    // Load configuration
    let cfg = match config::load_config("config.toml") {
        Ok(c) => {
            info!("Loaded config: {:?}", c);
            c
        }
        Err(e) => {
            error!("Error loading config: {}, using defaults.", e);
            config::Config {
                ipt_path: "/usr/sbin".to_string(), 
                fwcmd_path: "/usr/sbin".to_string(),
                expires: 3600,
                whitelist: vec!["127.0.0.1".to_string(), "::1".to_string()],
                has_ipv6: true,
                nocreate: false,
            }
        }
    };

    // Setup firewall
    info!("Setting up firewall...");
    if let Err(e) = firewall::setup_firewall(&cfg) {
        error!("Failed to setup firewall: {}", e);
        std::process::exit(1); 
    }
    info!("Firewall setup completed.");


    // Instantiate IpTracker and wrap it in Arc<Mutex<T>>
    let ip_tracker = Arc::new(Mutex::new(tracking::IpTracker::new(
        1.0, // block_threshold
        cfg.ipt_path.clone(),
        cfg.expires, // expires_seconds
    )));
    info!(
        "IpTracker initialized. Block threshold: {}, ipt_path: {}, expires_seconds: {}",
        1.0, cfg.ipt_path, cfg.expires
    );
    
    let sig_ip_tracker = Arc::clone(&ip_tracker); // Clone for SIGUSR1 handler

    // Register signal handlers in a new thread
    // Signals iterator needs to be handled in its own thread.
    let mut signals = Signals::new(&[SIGINT, SIGTERM, SIGUSR1]).expect("Failed to register signal iterator");

    std::thread::spawn(move || {
        for sig in signals.forever() {
            match sig {
                SIGINT | SIGTERM => {
                    info!("\nReceived termination signal (SIGINT/SIGTERM). Shutting down...");
                    sig_term_now.store(true, Ordering::Relaxed);
                }
                SIGUSR1 => {
                    info!("\nReceived SIGUSR1. Dumping IpTracker state:");
                    match sig_ip_tracker.lock() {
                        Ok(tracker) => {
                            if tracker.tracked_ips.is_empty() {
                                info!("  No IPs currently tracked.");
                            } else {
                                info!("  Tracked IPs ({}):", tracker.tracked_ips.len());
                                for (ip, state) in tracker.tracked_ips.iter() {
                                    let last_seen_secs = state.last_seen.duration_since(UNIX_EPOCH)
                                        .map_or_else(|_| "N/A".to_string(), |d| d.as_secs().to_string());
                                    info!(
                                        "  - IP: {}, Score: {:.2}, Blocked: {}, IPv6: {}, Last Seen: {} (epoch s)",
                                        ip, state.score, state.blocked, state.is_ipv6, last_seen_secs
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to lock IpTracker for SIGUSR1 dump: {}", e);
                        }
                    }
                }
                _ => {} // Should not happen with the registered signals
            }
        }
    });


    // Load patterns
    let mut all_patterns: Vec<patterns::FilterGroup> = Vec::new();
    info!("Loading patterns from directory: {}", cfg.patterns_path);

    match std::fs::read_dir(&cfg.patterns_path) {
        Ok(entries) => {
            for entry_result in entries {
                match entry_result {
                    Ok(entry) => {
                        let path = entry.path();
                        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                            info!("Attempting to load patterns from file: {:?}", path);
                            match patterns::load_patterns_from_file(path.to_str().unwrap_or_default()) {
                                Ok(loaded_groups) => {
                                    let num_loaded = loaded_groups.len();
                                    all_patterns.extend(loaded_groups);
                                    info!("Successfully loaded {} groups from {:?}.", num_loaded, path);
                                }
                                Err(e) => {
                                    error!("Error loading patterns from {:?}: {}", path, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error reading directory entry in {}: {}", cfg.patterns_path, e);
                    }
                }
            }
        }
        Err(e) => {
            error!("Failed to read patterns directory '{}': {}. Ensure it exists and has correct permissions.", cfg.patterns_path, e);
            // Depending on strictness, we might want to exit here if no patterns can be loaded.
            // For now, we'll continue, and it will operate with an empty pattern set if none are loaded.
        }
    }
    
    if all_patterns.is_empty() {
        warn!("No patterns loaded from '{}'. Tallow will run but may not block IPs effectively without patterns.", cfg.patterns_path);
    } else {
        info!("Total pattern groups loaded: {}", all_patterns.len());
    }

    info!("Attempting to open journal...");
    let mut journal = match journal::open_journal() {
        Ok(j) => {
            info!("Journal opened successfully.");
            j
        }
        Err(e) => {
            error!("Failed to open journal: {}", e);
            if e.to_string().contains("No such file or directory") || e.to_string().contains("does not exist") {
                error!("Systemd journal seems unavailable. This application requires systemd.");
            }
            std::process::exit(1);
        }
    };

    info!("Adding filter _COMM=sshd to journal (for log monitoring)...");
    if let Err(e) = journal::add_filter(&mut journal, "_COMM", "sshd") {
        error!("Failed to add journal filter for log monitoring: {}", e);
    } else {
        info!("Journal filter added for log monitoring.");
    }

    info!("Seeking to journal tail...");
    if let Err(e) = journal::seek_to_tail(&mut journal) {
        error!("Failed to seek to journal tail: {}", e);
        std::process::exit(1);
    }
    info!("Seeked to journal tail.");

    info!("\nMonitoring journal for new messages (Ctrl+C or SIGTERM to stop, kill -SIGUSR1 <pid> to dump state)...");
    
    // Main loop
    'main_loop: loop { 
        if term_now.load(Ordering::Relaxed) {
            info!("Termination flag set, exiting main loop.");
            break 'main_loop;
        }

        if let Ok(mut tracker) = ip_tracker.lock() {
            tracker.prune();
        } else {
            error!("Failed to lock IpTracker for pruning. Skipping prune cycle.");
        }

        match journal.wait(Some(Duration::from_millis(500))) { 
            Ok(wait_result) => {
                match wait_result {
                    JournalWaitResult::Nop => { /* Timeout, loop to check term_now */ }
                    JournalWaitResult::Append => { 
                        while let Ok(Some(message)) = journal::next_message(&mut journal) {
                            if term_now.load(Ordering::Relaxed) { // Check before expensive matching
                                info!("Termination flag set during message burst, exiting.");
                                break 'main_loop;
                            }
                            trace!("Received message: {}", message);
                            match patterns::match_message(&message, &all_patterns) {
                                Some((ip, score, ban_val)) => {
                                    debug!("Pattern MATCH: IP={}, Score={}, InstantBanVal={}", ip, score, ban_val);
                                    if let Ok(mut tracker) = ip_tracker.lock() {
                                        tracker.process_ip_match(ip, score, ban_val);
                                    } else {
                                         error!("Failed to lock IpTracker for processing IP match. Skipping.");
                                    }
                                }
                                None => { trace!("No pattern match for: {}", message); }
                            }
                        }
                    }
                    JournalWaitResult::Invalidate => {
                        warn!("Journal invalidated. Re-seeking to tail...");
                        if let Err(e) = journal::seek_to_tail(&mut journal) {
                            error!("Failed to re-seek to journal tail after invalidation: {}", e);
                            break 'main_loop; 
                        }
                    }
                }
            }
            Err(e) => { 
                if e.kind() == std::io::ErrorKind::Interrupted {
                    if term_now.load(Ordering::Relaxed) {
                         info!("Interrupted by signal, termination flag set. Exiting.");
                         break 'main_loop;
                    }
                    debug!("Journal wait interrupted by signal, continuing..."); 
                    continue;
                }
                error!("Error waiting for journal message: {}", e);
                std::thread::sleep(Duration::from_secs(1)); 
            }
        }
    }
    info!("Application terminated.");
}
