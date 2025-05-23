# Tallow-Rust

## Project Purpose

Tallow-Rust is a Rust-based alternative to Fail2ban, designed to enhance server security by monitoring the systemd journal for suspicious activities, primarily focusing on services like SSHD. When malicious patterns are detected, Tallow-Rust blocks the offending IP addresses using `ipset` and integrates with `firewalld` or `iptables`.

This project is a complete rewrite of the original Tallow (written in C) in Rust, aiming for improved safety, performance, and maintainability.

## Basic Mechanism

Tallow-Rust operates through the following steps:

1.  **Journal Monitoring:** It reads entries from the systemd journal, targeting specific services (e.g., `sshd` by default).
2.  **Pattern Matching:** Log messages are matched against regular expression patterns defined in JSON configuration files. These patterns identify malicious behavior, such as repeated failed login attempts.
3.  **IP Tracking & Scoring:** When a log message matches a pattern, Tallow-Rust extracts the source IP address. Each IP is tracked, and a score is accumulated based on the matched patterns.
4.  **Blocking:**
    *   If a pattern indicates an "instant block," the IP is immediately blocked.
    *   If an IP's cumulative score exceeds a configurable threshold, it is blocked.
    *   Blocking is performed using `ipset` to add the IP to a blocklist. These ipsets are then used by `firewalld` (if active) or `iptables` rules to drop traffic from the blocked IPs.
5.  **IP Pruning:** Tracked IPs that have not been seen for a configurable duration (`expires`) are removed from active tracking. Blocked IPs also expire from ipsets based on the `expires` setting used when creating the ipsets.

## Configuration

Tallow-Rust is configured via a TOML file, typically located at `/etc/tallow/tallow.toml`.

Key configuration options include:

*   `ipt_path` (String): Path to `iptables` and `ipset` utilities. Default: `"/usr/sbin"`.
*   `fwcmd_path` (String): Path to `firewall-cmd` utility. Default: `"/usr/sbin"`.
*   `expires` (Integer): Default duration in seconds for entries in ipsets (used for automatic unblocking by `ipset` itself) and for pruning inactive IPs from internal tracking. Default: `3600`.
*   `whitelist` (Array of Strings): A list of IP addresses that should never be blocked. Default: `["127.0.0.1", "::1"]`.
*   `has_ipv6` (Boolean): Enable or disable IPv6 support (creation of IPv6 ipsets and rules). Default: `true`.
*   `nocreate` (Boolean): If true, Tallow-Rust will not attempt to create or modify any firewall rules or ipsets. It will only perform logging and internal IP tracking. Default: `false`.
*   `patterns_path` (String): Path to the directory containing JSON pattern files (e.g., `sshd.json`, `dovecot.json`). Default: `"/etc/tallow/patterns"`. *(This option will be added to the config struct in a future step)*.

### Logging

Logging is controlled via the `RUST_LOG` environment variable. For example:
`RUST_LOG=info tallow_rust`
Supported levels: `error`, `warn`, `info`, `debug`, `trace`.

## Building

To build Tallow-Rust:
```bash
cargo build --release
```
The resulting binary will be located at `target/release/tallow_rust`.

## Running

Tallow-Rust can be run directly or as a systemd service.

*   **Directly:**
    ```bash
    sudo /path/to/target/release/tallow_rust 
    # Or after installation, typically:
    # sudo /usr/sbin/tallow_rust
    ```
    Ensure it's run with root privileges to interact with the firewall and ipset.

*   **Via Systemd:**
    A systemd service file (`tallow_rust.service`) is provided. Once installed (typically to `/etc/systemd/system/`), you can manage it with:
    ```bash
    sudo systemctl start tallow_rust
    sudo systemctl enable tallow_rust
    sudo systemctl status tallow_rust
    ```

## Credit

This project is a Rust rewrite of the original Tallow security tool. Credit goes to the original author(s) for the concept and design.
