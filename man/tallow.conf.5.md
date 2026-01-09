% TALLOW.CONF(5)
% Auke Kok `<sofar@foo-projects.org>`

# tallow.conf

The tallow configuration file

## NAME

tallow.conf - Tallow daemon configuration file

## SYNOPSIS

`/etc/tallow.conf`

## DESCRIPTION

This file is read on startup by the tallow(1) daemon, and can
be used to provide options to the tallow daemon. If not present,
tallow will operate with built-in defaults.

## OPTIONS

`backend`=`nft|iptables|firewall-cmd`
Tallow can operate using 3 different methods to block IP
addresses. Using this option forces tallow to use one of the supported
backends.

The original version only supported using iptables(1)/ip6tables(1)
and ipset(1). This is the `iptables` backend.

Later, support for firewall-cmd(1) was added. firewall-cmd itself
uses ipsets and nftables or iptables.

The `nft` backend uses `netfilter` or `nft` to setup tables and IP
address sets.

All these three backends work relatively well with or without
firewall-cmd and other firewalls, and have slightly different
implications for rule ordering and setup and teardown rules. The
simplest and most reliable backend is `nft` and this is the current
default backend choice, even if firewalld(1) is running.

Tallow will make sure that `nft` is present and working before using
it, and will try to use firewall-cmd before falling back to iptables
as a backend.

`fwcmd_path`=`<string>`
Specifies the location of the ipset(1) firewall-cmd(1) programs. By
default, tallow will look in "/usr/sbin" for them.

`ipt_path`=`<string>`
Specifies the location of the ipset(1) program and iptables(1) or
ip6tables(1) programs. By default, tallow will look in "/usr/sbin"
for them.

`nft_path`=`<string>`
Specifies the location of the nft(1) program. By default, tallow will
look in "/usr/sbin" for it.

`expires`=`<int>`
The number of seconds that IP addresses are blocked for. Note that
due to the implementation, IP addresses may be blocked for much
longer than this period. If IP addresses are seen, but not
blocked within this period, they are also removed from the
watch list. Defaults to 3600s.

`whitelist`=`<ip address|pattern>`
Specify an IP address or `pattern` that should never be
blocked. Multiple IP addresses can be included by repeating the
`whitelist` option several times. By default, 127.0.0.1, 192.168., and
10. are whitelisted. If you create a manual whitelist, you must include
these entries if you want to continue them to be whitelisted as
well, otherwise they will be omitted from the whitelist.

If the last character of the listed ip adress is a `.` or a `:`, then
the matching is only performed on the leftmost characters of an IP
address against the whitelist entry. For instance, if you whitelist
`10.` then all IP addresses in the `10/8` subnet mask will match this
whitelist entry and never be blocked.

`ipv6`=`<0|1>`
Enable or disable ipv6 (ip6tables) support. Ipv6 is disabled
automatically on systems that do not appear to have ipv6 support
and enabled when ipv6 is present. Use this option to explicitly
disable ipv6 support if your system does not have ipv6 or is
missing ip6tables. Even with ipv6 disabled, tallow will track
and log ipv6 addresses.

`nocreate`=`<0|1>` Disable the creation of firewall rules and ipset sets. By
default, tallow will create new firewall-cmd(1) or iptables(1) and ip6tables(1)
rules when needed automatically. If set to `1`, `tallow(1)` will not create any
new firewall DROP rules or ipset sets that are needed work. You should create
them manually before tallow starts up and remove them afterwards using the sets
of commands below.

Use the following commands if you're using iptables(1):

  ```
  ipset create tallow hash:ip family inet timeout 3600
  iptables -t filter -I INPUT 1 -m set --match-set tallow src -j DROP

  ipset create tallow6 hash:ip family inet6 timeout 3600
  ip6tables -t filter -I INPUT 1 -m set --match-set tallow6 src -j DROP
  ```

Use the following commands if you're using firewalld(1):

```
  firewall-cmd --permanent --new-ipset=tallow --type=hash:ip --family=inet --option=timeout=3600
  firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 -m set --match-set tallow src -j DROP

  firewall-cmd --permanent --new-ipset=tallow6 --type=hash:ip --family=inet6 --option=timeout=3600
  firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT 1 -m set --match-set tallow6 src -j DROP

  ```

Use the following commands if you're using nft(1):

```
  nft add table inet tallow_table { chain tallow_chain { type filter hook input priority filter\; policy accept\; }\; }
  nft add set inet tallow_table tallow_set { type ipv4_addr\; timeout 3600s \;
  nft add rule inet tallow_table tallow_chain ip saddr @tallow_set drop
  nft add set inet tallow_table tallow6_set { type ipv6_addr\; timeout 3600s \;}
  nft add rule inet tallow_table tallow_chain ip6 saddr @tallow6_set drop
  ```

## SEE ALSO

tallow(1), tallow.patterns(5)
