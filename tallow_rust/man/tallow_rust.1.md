% tallow_rust(1) Tallow-Rust Manual
% Version 0.1.0

# NAME

tallow_rust - an IP address blocking tool based on systemd journal monitoring

# SYNOPSIS

**tallow_rust**

# DESCRIPTION

**tallow_rust** monitors the systemd journal for log messages matching predefined patterns, typically indicating malicious activity such as repeated failed login attempts. Upon detecting such patterns, it extracts the source IP address and takes action to block it using `ipset` and either `firewalld` or `iptables`.

The primary goal of **tallow_rust** is to enhance server security by automatically blocking attackers. It is a Rust rewrite of the original Tallow tool.

Configuration is handled via a TOML file, typically located at `/etc/tallow/tallow.toml`. This file defines paths to firewall utilities, default expiration times for blocks, IP whitelists, IPv6 support, and paths to JSON pattern files that define how malicious log entries are detected.

**tallow_rust** operates as a daemon and requires root privileges to interact with the system firewall and `ipset`.

# OPTIONS

**tallow_rust** currently does not accept command-line options. All configuration is managed through its configuration file.

# CONFIGURATION

See **tallow_rust.conf**(5) for details on the configuration file format and options. Patterns for matching log entries are defined in JSON files, as described in **tallow_rust.patterns**(5).

# LOGGING

Logging behavior is controlled by the `RUST_LOG` environment variable. For example, to set the log level to info:
`RUST_LOG=info tallow_rust`

Supported log levels include: `error`, `warn`, `info`, `debug`, `trace`.

# FILES

*   `/etc/tallow/tallow.toml` - Main configuration file.
*   `/etc/tallow/patterns/` - Default directory for JSON pattern definition files.

# SEE ALSO

**tallow_rust.conf**(5), **tallow_rust.patterns**(5), **ipset**(8), **firewall-cmd**(1), **iptables**(8), **systemd.journal-fields**(7)

# BUGS

Please report any bugs on the project's issue tracker.

# AUTHOR

This man page is for the Rust version of Tallow. The original Tallow concept and design credit goes to its initial authors.
