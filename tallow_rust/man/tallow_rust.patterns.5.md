% tallow_rust.patterns(5) Tallow-Rust Manual
% Version 0.1.0

# NAME

tallow_rust.patterns - JSON pattern definition files for tallow_rust(1)

# SYNOPSIS

Pattern files are typically located in `/etc/tallow/patterns/` (or the directory specified by `patterns_path` in `tallow_rust.conf`(5)) and must end with `.json`.

# DESCRIPTION

**tallow_rust** uses JSON files to define patterns for matching against systemd journal entries. These patterns determine which log messages are considered malicious and how they contribute to an IP address's score.

Each JSON file should contain an array of "Filter Group" objects.

# FILTER GROUP OBJECT

A Filter Group object defines a set of patterns that are typically related, often by the service they target (e.g., `sshd`, `dovecot`). It has the following keys:

**filter** (String, required)
:   A systemd journal filter string used to select relevant journal entries. Examples include `"_COMM=sshd"` or `"SYSLOG_IDENTIFIER=dovecot"`. While **tallow_rust** currently applies a primary journal filter at startup (e.g., for `_COMM=sshd`), this field is intended for future granularity or for tools that might pre-filter logs before sending them to a Tallow instance. The patterns within this group will be applied to messages obtained from a journal source that ideally matches this filter.

**items** (Array of PatternItem objects, required)
:   An array of `PatternItem` objects, each defining a specific regex pattern to match.

# PATTERN ITEM OBJECT

A PatternItem object defines a single regular expression and its associated actions. It has the following keys:

**pattern** (String, required)
:   The regular expression to match against the "MESSAGE" field of a journal entry.
:   **tallow_rust** will automatically strip a leading `MESSAGE=` from this string before compiling the regex if it is present. This allows for compatibility with patterns that explicitly state the journal field.
:   The regex must contain at least one capture group. The first capture group is expected to be the IP address of the offending client.

**score** (Float, required)
:   The score to add to an IP address's total when this pattern is matched. A higher score indicates more suspicious behavior. If an IP's total score exceeds the `block_threshold` (defined in `tallow_rust.conf`(5)), the IP will be blocked.

**ban** (Integer, required)
:   If this value is greater than 0, matching this pattern will cause the IP address to be "instantly blocked" for the number of seconds specified by this value. This overrides the normal score accumulation and threshold check. A value of 0 means no instant block.

# EXAMPLE

```json
[
  {
    "filter": "_COMM=sshd",
    "items": [
      {
        "pattern": "MESSAGE=Failed password for invalid user .* from ([0-9a-z:.]+) port \\d+ ssh2",
        "score": 2.5,
        "ban": 0
      },
      {
        "pattern": "MESSAGE=Received disconnect from ([0-9a-z:.]+) port \\d+:\\d+: Too many authentication failures \\[preauth\\]",
        "score": 0.0,
        "ban": 3600
      }
    ]
  },
  {
    "filter": "SYSLOG_IDENTIFIER=dovecot",
    "items": [
      {
        "pattern": "service=auth, event=failed, rip=([0-9a-z:.]+), lip=",
        "score": 1.0,
        "ban": 0
      }
    ]
  }
]
```

In this example:
*   The first filter group targets `sshd` logs.
    *   A "Failed password for invalid user" message adds 2.5 to the IP's score.
    *   A "Too many authentication failures" message results in an instant 1-hour ban (3600 seconds) and adds 0.0 to the score.
*   The second filter group targets `dovecot` logs (identified by `SYSLOG_IDENTIFIER`).
    *   A failed authentication event adds 1.0 to the IP's score.

# SEE ALSO

**tallow_rust**(1), **tallow_rust.conf**(5), **regex**(7), **systemd.journal-fields**(7)

# AUTHOR

This man page is for the Rust version of Tallow. The original Tallow concept and design credit goes to its initial authors.
