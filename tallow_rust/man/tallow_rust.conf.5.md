% tallow_rust.conf(5) Tallow-Rust Manual
% Version 0.1.0

# NAME

tallow_rust.conf - configuration file for tallow_rust(1)

# SYNOPSIS

`/etc/tallow/tallow.toml`

# DESCRIPTION

**tallow_rust** uses a configuration file in TOML format to control its behavior. The default location for this file is `/etc/tallow/tallow.toml`.

This page describes the available configuration options.

# OPTIONS

All options are key-value pairs within the TOML structure.

**ipt_path**
:   Path to the directory containing `iptables` and `ipset` utilities.
:   *Type:* String
:   *Default:* `"/usr/sbin"`

**fwcmd_path**
:   Path to the directory containing the `firewall-cmd` utility.
:   *Type:* String
:   *Default:* `"/usr/sbin"`

**expires**
:   Default duration in seconds for entries in ipsets. This is used by `ipset` itself for automatic unblocking of IPs. It is also used by **tallow_rust** to determine when to prune inactive (non-blocked) or expired (previously blocked) IP addresses from its internal tracking.
:   *Type:* Integer
:   *Default:* `3600` (1 hour)

**whitelist**
:   An array of IP addresses (IPv4 or IPv6) that should never be blocked by **tallow_rust**.
:   *Type:* Array of Strings
:   *Default:* `["127.0.0.1", "::1"]`

**has_ipv6**
:   Enables or disables IPv6 support. If `true`, **tallow_rust** will create and manage IPv6 ipsets (e.g., `tallow6`) and corresponding firewall rules.
:   *Type:* Boolean
:   *Default:* `true`

**nocreate**
:   If set to `true`, **tallow_rust** will not attempt to create or modify any firewall rules or ipsets. It will perform all other actions, including logging and internal IP tracking, but will not interact with the system's firewall. This can be useful for testing or in environments where firewall management is handled externally.
:   *Type:* Boolean
:   *Default:* `false`

**patterns_path**
:   Path to the directory containing JSON pattern definition files (e.g., `sshd.json`, `dovecot.json`). Each file in this directory that ends with `.json` will be loaded.
:   *Type:* String
:   *Default:* `"/etc/tallow/patterns"` *(Note: This option will be added to the `Config` struct in a future development step. The default path is a planned value.)*

# EXAMPLE

```toml
# Example /etc/tallow/tallow.toml
ipt_path = "/usr/sbin"
fwcmd_path = "/usr/sbin"
expires = 7200 # 2 hours
whitelist = ["127.0.0.1", "::1", "192.168.1.100"]
has_ipv6 = true
nocreate = false
# patterns_path = "/etc/tallow/patterns" # Uncomment when implemented
```

# SEE ALSO

**tallow_rust**(1), **tallow_rust.patterns**(5), **toml**(5)

# AUTHOR

This man page is for the Rust version of Tallow. The original Tallow concept and design credit goes to its initial authors.
