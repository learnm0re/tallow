use std::collections::HashMap;
use std::time::SystemTime;
use std::process::Command;
use std::error::Error;
use log::{info, warn, error, debug}; // Added log import

#[derive(Debug, Clone)]
pub struct IpState {
    pub score: f32,
    pub last_seen: SystemTime,
    pub blocked: bool,
    pub is_ipv6: bool,
}

#[derive(Debug)]
pub struct IpTracker {
    pub tracked_ips: HashMap<String, IpState>,
    pub block_threshold: f32,
    pub ipt_path: String, // Path to ipset/iptables utilities
    pub expires_seconds: i32,
}

impl IpTracker {
    pub fn new(block_threshold: f32, ipt_path: String, expires_seconds: i32) -> Self {
        IpTracker {
            tracked_ips: HashMap::new(),
            block_threshold,
            ipt_path,
            expires_seconds,
        }
    }

    fn determine_is_ipv6(ip_address: &str) -> bool {
        ip_address.contains(':')
    }

    // block_ip takes &self, so it doesn't conflict with mutable borrows of self.tracked_ips
    // as long as its execution doesn't overlap with those borrows.
    pub fn block_ip(&self, ip_address: &str, is_ipv6: bool, duration_seconds: Option<i32>) -> Result<(), Box<dyn Error>> {
        let ipset_name = if is_ipv6 { "tallow6" } else { "tallow" };
        let ipset_tool_path = format!("{}/ipset", self.ipt_path.trim_end_matches('/'));

        let mut command_args = vec!["-!".to_string(), "add".to_string(), ipset_name.to_string(), ip_address.to_string()];
        if let Some(duration) = duration_seconds {
            if duration > 0 {
                command_args.push("timeout".to_string());
                command_args.push(duration.to_string());
            }
        }

        debug!("Executing ipset command: {} {}", ipset_tool_path, command_args.join(" "));

        let output = Command::new(&ipset_tool_path)
            .args(&command_args)
            .output()?;

        if output.status.success() {
            info!("Successfully added/updated IP {} in ipset {}.", ip_address, ipset_name);
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(
                "Error executing ipset for IP {}: {}. Exit code: {:?}",
                ip_address,
                stderr,
                output.status.code()
            );
            Err(format!(
                "ipset command failed for {}: {}. Exit code: {:?}",
                ip_address,
                stderr,
                output.status.code()
            ).into())
        }
    }

    pub fn process_ip_match(&mut self, ip_address_str: String, weight: f32, instant_block_duration: i32) {
        let now = SystemTime::now();
        let initial_is_ipv6 = Self::determine_is_ipv6(&ip_address_str);

        // Scope for mutable borrow of self.tracked_ips via 'entry'
        let (current_score, previously_blocked, actual_is_ipv6) = {
            let entry = self.tracked_ips.entry(ip_address_str.clone()).or_insert_with(|| IpState {
                score: 0.0,
                last_seen: now,
                blocked: false,
                is_ipv6: initial_is_ipv6,
            });
            
            entry.score += weight;
            entry.last_seen = now;
            (entry.score, entry.blocked, entry.is_ipv6) // Extract values needed outside this scope
        };
        
        // Now 'entry' (and its mutable borrow) is out of scope.
        // We can call self.block_ip(&self, ...)

        debug!(
            "Processing IP: {}, Current Score: {:.2}, Previously Blocked: {}",
            ip_address_str, current_score, previously_blocked
        );

        let mut should_be_marked_blocked_internally = previously_blocked;

        if instant_block_duration > 0 {
            info!(
                "Attempting instant block for IP: {} ({}s duration)",
                ip_address_str, instant_block_duration
            );
            match self.block_ip(&ip_address_str, actual_is_ipv6, Some(instant_block_duration)) {
                Ok(_) => {
                    info!("IP: {} successfully instant-blocked.", ip_address_str);
                    should_be_marked_blocked_internally = true;
                }
                Err(e) => {
                    error!("Failed to instant block IP {}: {}", ip_address_str, e);
                    should_be_marked_blocked_internally = true; // Mark as blocked even if command fails
                }
            }
        } else if current_score >= self.block_threshold && !previously_blocked {
            info!(
                "Score threshold {:.2} reached for IP: {}. Attempting block.",
                 self.block_threshold, ip_address_str
            );
            match self.block_ip(&ip_address_str, actual_is_ipv6, None) {
                Ok(_) => {
                    info!("IP: {} successfully blocked (score threshold).", ip_address_str);
                    should_be_marked_blocked_internally = true;
                }
                Err(e) => {
                    error!("Failed to block IP {} (score threshold): {}", ip_address_str, e);
                    should_be_marked_blocked_internally = true; // Mark as blocked even if command fails
                }
            }
        }

        // Update the 'blocked' status in the HashMap after block_ip calls are done.
        if should_be_marked_blocked_internally {
            if let Some(entry_to_update) = self.tracked_ips.get_mut(&ip_address_str) {
                entry_to_update.blocked = true;
            }
        }

        if !should_be_marked_blocked_internally && previously_blocked {
            // This state means it was already blocked and no new block condition was met this cycle.
             debug!("IP: {} was already marked as blocked and remains so. Current score: {:.2}", ip_address_str, current_score);
        } else if !should_be_marked_blocked_internally && !previously_blocked {
            // Not blocked now, wasn't blocked before, and didn't meet conditions to be blocked this cycle.
            debug!("IP: {} score updated to {:.2}. Not meeting threshold or conditions for blocking this cycle.", ip_address_str, current_score);
        }
        // If should_be_marked_blocked_internally is true, it's because a block was applied or re-applied.
        // If it's false and previously_blocked was true, it means it's still considered blocked from before.
    }

    pub fn prune(&mut self) {
        let current_time = SystemTime::now();
        let mut ips_to_remove = Vec::new();
        let mut unblocked_count = 0;
        let mut inactive_count = 0;

        for (ip_address, ip_state) in self.tracked_ips.iter() {
            match current_time.duration_since(ip_state.last_seen) {
                Ok(duration_since_last_seen) => {
                    if duration_since_last_seen.as_secs() > self.expires_seconds as u64 {
                        if ip_state.blocked {
                            info!(
                                "IP {} was blocked, now considered unblocked due to expiry ({}s > {}s). Removing from active tracking.",
                                ip_address, duration_since_last_seen.as_secs(), self.expires_seconds
                            );
                            unblocked_count += 1;
                        } else {
                            debug!(
                                "IP {} was not blocked, inactive for {}s (>{_expires}s). Removing from active tracking.",
                                ip_address, duration_since_last_seen.as_secs(), _expires = self.expires_seconds
                            );
                            inactive_count += 1;
                        }
                        ips_to_remove.push(ip_address.clone());
                    }
                }
                Err(e) => {
                    warn!("Error calculating duration for IP {}: {}. Skipping prune for this IP.", ip_address, e);
                }
            }
        }

        if !ips_to_remove.is_empty() {
            debug!("Pruning {} IPs ({} unblocked due to expiry, {} inactive).", ips_to_remove.len(), unblocked_count, inactive_count);
        }

        for ip_address in ips_to_remove {
            self.tracked_ips.remove(&ip_address);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn create_tracker() -> IpTracker {
        IpTracker::new(1.0, "/sbin/ipset".to_string(), 3600)
    }
    
    fn create_tracker_with_expiry(expires: i32) -> IpTracker {
        IpTracker::new(1.0, "/sbin/ipset".to_string(), expires)
    }

    #[test]
    fn test_determine_is_ipv6() {
        assert!(IpTracker::determine_is_ipv6("::1"));
        assert!(IpTracker::determine_is_ipv6("2001:db8::1"));
        assert!(!IpTracker::determine_is_ipv6("127.0.0.1"));
        assert!(!IpTracker::determine_is_ipv6("192.168.1.1"));
    }

    #[test]
    fn test_process_ip_new() {
        let mut tracker = create_tracker();
        let ip = "1.2.3.4".to_string();
        let now_before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        tracker.process_ip_match(ip.clone(), 0.5, 0);

        let now_after = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let state = tracker.tracked_ips.get(&ip).unwrap();
        assert_eq!(state.score, 0.5);
        assert!(!state.blocked);
        assert!(!state.is_ipv6);
        let state_last_seen_secs = state.last_seen.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert!(state_last_seen_secs >= now_before && state_last_seen_secs <= now_after);
    }

    #[test]
    fn test_process_ip_accumulate_score() {
        let mut tracker = create_tracker();
        let ip = "1.2.3.5".to_string();

        tracker.process_ip_match(ip.clone(), 0.3, 0);
        let state1 = tracker.tracked_ips.get(&ip).unwrap();
        assert_eq!(state1.score, 0.3);

        tracker.process_ip_match(ip.clone(), 0.4, 0);
        let state2 = tracker.tracked_ips.get(&ip).unwrap();
        assert_eq!(state2.score, 0.3 + 0.4); // Check exact float comparison later if problematic
        assert!((state2.score - 0.7).abs() < f32::EPSILON);

    }

    #[test]
    fn test_process_ip_reaches_threshold_no_instant_block() {
        let mut tracker = create_tracker(); // block_threshold = 1.0
        let ip = "1.2.3.6".to_string();

        tracker.process_ip_match(ip.clone(), 0.5, 0);
        assert!(!tracker.tracked_ips.get(&ip).unwrap().blocked, "Should not be blocked yet");

        tracker.process_ip_match(ip.clone(), 0.6, 0); // Total score 1.1
        // process_ip_match sets state.blocked = true if block_ip is attempted, even if it fails.
        // Since block_ip is not mocked here, we only check the internal state.
        assert!(tracker.tracked_ips.get(&ip).unwrap().blocked, "Should be marked as blocked after reaching threshold");
    }
    
    #[test]
    fn test_process_ip_already_blocked_score_increases_no_reblock_attempt() {
        let mut tracker = create_tracker(); // block_threshold = 1.0
        let ip = "1.2.3.10".to_string();

        // First, get it blocked
        tracker.process_ip_match(ip.clone(), 1.5, 0); 
        assert!(tracker.tracked_ips.get(&ip).unwrap().blocked);
        assert_eq!(tracker.tracked_ips.get(&ip).unwrap().score, 1.5);

        // Then, another match. Score should increase, but no new block attempt logic path for score threshold
        // The log output from process_ip_match would show "IP: ... was already marked as blocked..."
        tracker.process_ip_match(ip.clone(), 0.5, 0);
        assert!(tracker.tracked_ips.get(&ip).unwrap().blocked); // Still blocked
        assert_eq!(tracker.tracked_ips.get(&ip).unwrap().score, 2.0); 
    }


    #[test]
    fn test_process_ip_instant_block() {
        let mut tracker = create_tracker();
        let ip = "1.2.3.7".to_string();

        tracker.process_ip_match(ip.clone(), 0.1, 300); // instant_block_duration = 300
        assert!(tracker.tracked_ips.get(&ip).unwrap().blocked, "Should be marked as blocked due to instant_block");
        assert_eq!(tracker.tracked_ips.get(&ip).unwrap().score, 0.1); // Score is still updated
    }

    #[test]
    fn test_prune_unblocked_ip() {
        let mut tracker = create_tracker_with_expiry(5); // expires in 5 seconds
        let ip = "1.2.3.8".to_string();
        let old_time = SystemTime::now() - Duration::from_secs(10);

        tracker.tracked_ips.insert(ip.clone(), IpState {
            score: 0.1,
            last_seen: old_time,
            blocked: false,
            is_ipv6: false,
        });
        
        assert!(tracker.tracked_ips.contains_key(&ip));
        tracker.prune();
        assert!(!tracker.tracked_ips.contains_key(&ip), "Unblocked IP should be pruned after expiry");
    }

    #[test]
    fn test_prune_blocked_ip() {
        let mut tracker = create_tracker_with_expiry(5);
        let ip = "1.2.3.9".to_string();
        let old_time = SystemTime::now() - Duration::from_secs(10);

        tracker.tracked_ips.insert(ip.clone(), IpState {
            score: 1.5, // Assume it was blocked due to score
            last_seen: old_time,
            blocked: true,
            is_ipv6: false,
        });

        assert!(tracker.tracked_ips.contains_key(&ip));
        tracker.prune();
        assert!(!tracker.tracked_ips.contains_key(&ip), "Blocked IP should be pruned after expiry");
    }

    #[test]
    fn test_prune_active_ip() {
        let mut tracker = create_tracker_with_expiry(3600);
        let ip = "1.2.3.10".to_string();
        let recent_time = SystemTime::now() - Duration::from_secs(60); // Seen 60 seconds ago

        tracker.tracked_ips.insert(ip.clone(), IpState {
            score: 0.2,
            last_seen: recent_time,
            blocked: false,
            is_ipv6: false,
        });
        
        assert!(tracker.tracked_ips.contains_key(&ip));
        tracker.prune();
        assert!(tracker.tracked_ips.contains_key(&ip), "Active IP should not be pruned");
    }
     #[test]
    fn test_prune_active_blocked_ip() {
        let mut tracker = create_tracker_with_expiry(3600);
        let ip = "1.2.3.11".to_string();
        let recent_time = SystemTime::now() - Duration::from_secs(60);

        tracker.tracked_ips.insert(ip.clone(), IpState {
            score: 1.2, // High score
            last_seen: recent_time,
            blocked: true, // Marked as blocked
            is_ipv6: false,
        });
        
        assert!(tracker.tracked_ips.contains_key(&ip));
        tracker.prune();
        assert!(tracker.tracked_ips.contains_key(&ip), "Active blocked IP should not be pruned based on activity");
    }
}
