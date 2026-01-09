% TALLOW(1)
% Auke Kok `<sofar@foo-projects.org>`

# tallow

Reduce log clutter due to ssh login attempts.

## SYNOPSIS

`/usr/sbin/tallow`

## DESCRIPTION

`tallow` is a daemon that watches the systemd journal for messages
from the `sshd` service. It parses the messages and looks for
attempted random logins such as failed logins to the root account and
failed logins to invalid user accounts, and various other obviously
malicious login attempts that try things as forcing old protocols,
or weak key systems.

If such logins were detected, the offending IP address is stored in
a list. Items from this list are regularly purged, but if the amount
of times that a specific IP address is seen exceeds a threshold,
the IP address is blocked by inserting the appropriate firewall rules
using sets (either ipset(1) of nft(1) sets), causing further packets
from that ip address will be blocked.  Additionally, certain types
of login failure will trigger a short term ban of further packets
from the offending IP address immediately.

The system administrator needs to assure that the tallow and tallow6
ipsets are left alone and that the inserted iptables or netfilter rules
are properly matching on packets.

Care should be taken to assure that legitimate users are not
blocked inadvertently. You may wish to list any valid IP address
with the whitelist option in tallow.conf(5). Multiple addresses and 
ranges of IP addresses can be whitelisted.

## OPTIONS

The `tallow` daemon itself has no runtime configuration. All
configuration is done through the tallow.conf(5) config file.

## SIGNALS

The `USR1` signal causes `tallow` to print out it's internal tracking
table of IP addresses. This requires that tallow is compiled with
the `-DDEBUG=1` symbol passed to the compiler.

## SEE ALSO

systemd-journald(1), iptables(1), ipset(1), tallow.conf(5), tallow.patterns(5), nft(1)

## BUGS

`tallow` is `NOT A SECURITY SOLUTION`, nor does it protect against
random password logins. A attacker may still be able to logon to your
systems if you allow password logins.
