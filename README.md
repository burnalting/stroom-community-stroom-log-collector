# stroom-community-stroom-log-collector

# Log Collector and Stroom Proxy Poster (YAML Configuration)

## Overview

This Python script collects new log lines from rotated log files, enriches them (including with FQDNs for all detected IPv4 and IPv6 addresses), and posts them to one or more Stroom proxies using HTTP(S) with optional mutual TLS. It maintains state based on the timestamp of the last processed log line, ensuring no duplicate or missed events even across log file rotations. Queued files are aged out by time and size. The script is compatible with RHEL7+ and is fully configurable via a YAML file and command-line arguments.

---

## Features

- **YAML-based configuration** for all settings
- **Custom timestamp regexes** (`custom_formats`) per feed, tried before ISO8601
- **Timestamp-based state:** Only new log lines (by timestamp) are collected and posted.
- **Multiple log sources:** Supports any number of log files, each with its own settings.
- **Log rotation support:** Handles files with patterns like `base`, `base.timestamp`, etc.
- **ISO8601 timestamp extraction:** Defaults to ISO8601 with/without timezone, with robust fractional second support.
- **IPv4/IPv6/FQDN enrichment:** Appends FQDNs for all detected IPs in log lines.
- **JSON Log Line Support:** Allows for json fragments as logs, so enrichment is added as a json sub-fragment.
- **Comprehensive host metadata:** Adds all host IPs, FQDNs, nameservers, and system Timezone to HTTP headers when file posting.
- **Mutual TLS support:** Can use client cert/key and CA bundle for two-sided trust. Or no trust at all (not recommended)
- **Queue-first posting:** Always attempts to post any queued files, even if no new logs are found.
- **File aging:** Queued files are deleted if they exceed a time or size limit.
- **Configurable via YAML and command-line:** All settings in a single YAML file and/or via CLI.
- **ISO8601 localtime execution logs:** All actions are logged with local ISO8601 timestamps.
- **Option to run in test mode:** Files are generated but not posted to any proxy (`--test` flag).

---

## Example `config.yaml`

```
# Main list of Stroom proxy endpoints to post logs to (failover order)
stroom_proxies:
  - https://stroom-proxy1.example.com/stroom/datafeed
  - https://stroom-proxy2.example.com/stroom/datafeed

# TLS/SSL configuration for HTTPS requests
tls:
  ca_cert: "/etc/ssl/certs/ca-bundle.crt"  # Path to CA bundle for server verification
  # ca_cert: "false"                       # (string "false" disables verification, not recommended for production)
  # client_cert: "/etc/ssl/certs/client.crt" # (Optional) Path to client certificate for mutual TLS
  # client_key: "/etc/ssl/private/client.key" # (Optional) Path to client key for mutual TLS

# Default timeout (in seconds) for posting logs to proxies
timeout_seconds: 10

# List of log sources ("feeds") to monitor and post
feeds:
  - name: syslog                         # Unique identifier for this feed (used in state file)
    log_pattern: /var/log/syslog*        # Glob pattern for log files (rotated and base)
    feed_name: SYSLOG_FEED               # Stroom feed name to use in HTTP header
    proxy_overrides:
      - https://custom-proxy.example.com/stroom/datafeed  # (Optional) Use these proxies for this feed only
    headers:                             # (Optional) Additional HTTP headers for this feed
      Environment: Production
      LogType: Syslog
    custom_formats:                      # (Optional) List of custom timestamp regex/format pairs
      - regex: '^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})'
        format: '%b %d %H:%M:%S'         # For syslog: e.g. "Jul  7 14:32:01"
      - regex: '^(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})'
        format: '%d/%m/%Y %H:%M:%S'      # e.g. "07/07/2025 14:32:01"
      - regex: '^(\d+(\.\d+)?)'          # e.g. 1723295765.245
        format: 'epoch'
    enrich_ip: true                      # (Optional) If true, append FQDNs for all IPs in each line
    json_mode: false                     # (Optional) If true, treat the input line as a json fragment
    queue_time_limit_days: 32            # (Optional) Max age (days) for queued files for this feed
    queue_size_limit_mb: 8192            # (Optional) Max queue size (MB) for this feed
    timeout_seconds: 20                  # (Optional) Override global timeout for this feed

  - name: authlog
    log_pattern: /var/log/auth.log*
    feed_name: AUTH_FEED
    headers:
      Environment: Production
      LogType: Auth
    enrich_ip: true

  - name: nginx_access
    log_pattern: /var/log/nginx/access.log*
    feed_name: NGINX_ACCESS_FEED
    headers:
      Environment: Production
      LogType: NginxAccess
    custom_formats:                      # (Optional) List of custom timestamp regex/format pairs
      - regex: '^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+(?:Z|[+-]\d{2}:?\d{2}))'
        format: '%Y-%m-%dT%H:%M:%S.%f%z' # For 2025-07-07T07:45:02.000+10:00
      - regex: '^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})'
        format: '%b %d %H:%M:%S'         # For syslog: e.g. "Jul  7 14:32:01"
      - regex: '^(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})'
        format: '%d/%m/%Y %H:%M:%S'      # e.g. "07/07/2025 14:32:01"
    enrich_ip: true

# Default retention/queue settings (used if not overridden per-feed)
defaults:
  queue_time_limit_days: 21        # Max age (days) for queued files
  queue_size_limit_mb: 2048        # Max total size (MB) for queued files
```

---

## Configuration Reference

| YAML Key                        | Description                                                                                           |
|----------------------------------|------------------------------------------------------------------------------------------------------|
| `stroom_proxies`                 | List of default Stroom proxy URLs.                                                                   |
| `timeout_seconds`                | Default in seconds when posting to a stroom proxy                                                    |
| `tls`                            | TLS config for authentication (see below).                                                           |
| `feeds`                          | List of log sources, each with:                                                                      |
| `feeds[].name`                   | Unique feed name.                                                                                    |
| `feeds[].log_pattern`            | Glob pattern for log files (e.g., `/var/log/access.log*`).                                           |
| `feeds[].feed_name`              | Stroom feed name.                                                                                    |
| `feeds[].proxy_overrides`        | (Optional) List of proxies for this feed.                                                            |
| `feeds[].headers`                | (Optional) Key-value pairs for HTTP headers.                                                         |
| `feeds[].custom_formats`         | (Optional) List of `{regex, format}` for custom timestamp parsing.                                   |
| `feeds[].enrich_ip`              | (Optional) Add FQDNs for IPs in log lines (both IPv4 and IPv6) (see below).                          |
| `feeds[].json_mode`              | (Optional) Treat log line as json, so when adding optional FQDN's, they are correctly inserted       |
| `feeds[].queue_time_limit_days`  | (Optional) Max age for queued files (per feed).                                                      |
| `feeds[].queue_size_limit_mb`    | (Optional) Max size for queued files (per feed).                                                     |
| `feeds[].timeout_seconds`        | (Optional) Post timeout for this feed.                                                               |
| `defaults`                       | Default values for queue aging if not specified per feed (see below).                                |

---

## TLS/SSL Authentication

- **One-sided trust (default HTTPS):**  
  Only specify `ca_cert`. Do **not** specify `client_cert` or `client_key`.

- **Mutual TLS (two-sided trust):**  
  Specify all of `ca_cert`, `client_cert`, and `client_key` in the `tls` section.

- **Disabling TLS verification:**
  If you set `ca_cert`: `false` in your YAML config under tls, the script will not verify SSL certificates when posting to proxies. This is insecure and should only be used for testing. The script will also suppress any InsecureRequestWarning messages from the requests library.

---

## Command-line Options

| Option         | Description                        | Default Value               |
|----------------|------------------------------------|-----------------------------|
| `--config`     | Path to YAML configuration file    | `config.yaml`               |
| `--state-dir`  | Directory for state files          | `state`                     |
| `--queue-dir`  | Directory for queue files          | `queue`                     |
| `--debug`      | Enable debug logging               | Off (INFO level)            |
| `--test`       | Generate files but do not post     | Off                         |

---

## Running the Script

1. **Install Requirements:**
   - Python 3.6+ (RHEL7+)
   - `requests` and `pyyaml` libraries:  
     ```
     pip install requests pyyaml
     ```
   - (Optional) `dnspython` for enhanced nameserver discovery:
     ```
     pip install dnspython
     ```

2. **Prepare Directory Structure:**
   - Place `stroom_log_collector.py` and `config.yaml` in the same directory (or specify paths via CLI).
   - Create `state/` and `queue/` subdirectories (or specify via CLI).

3. **Configure `config.yaml`:**
   - Define your Stroom proxies, TLS certificates, and feeds as shown above.

4. **Run the Script:**
   - Assume working directory is `/opt/stroom/stroom_log_collector`

python3 stroom_log_collector.py
--config /opt/stroom/stroom_log_collector/config.yaml
--state-dir /opt/stroom/stroom_log_collector/state
--queue-dir /opt/stroom/stroom_log_collector/queue


- The script can be scheduled via cron for regular execution.

---

## Script Behavior

- **State Tracking:**  
The script records the timestamp of the last processed log line for each feed in `state/<feed_name>.json`. On each run, it only processes lines with a newer timestamp.

- **Log Rotation:**  
Log files are processed in lexicographical order, with the base file processed last.

- **Posting:**  
- Any new log lines are written to a `.log.gz` file in the `queue/` directory.
- On every run, the script attempts to post all queued files, oldest first.
- If posting fails (e.g., network down), files remain in the queue for the next run.
- Can skip posting by sepecifying test mode on the command line via the `--test` command line option.

- **Mutual TLS:**  
If `client_cert` and `client_key` are specified in the `tls` section, the script uses them for two-sided trust when posting to proxies.

- **Header Enrichment:**  
The script adds the following headers to every post:
 - `MyIPAddresses`: All host IPs (IPv4 and IPv6, all interfaces)
 - `MyHosts`: All FQDNs for the host
 - `MyNameServer`: All nameservers discovered by multiple mechanisms
 - `TZ`: System Ianna Timezone
 - Plus any custom headers from the feed config

- **IP/FQDN Enrichment:**  
If `enrich_ip: true`, each log line is appended with `_resolv_: {ip0}={fqdn0} {ip1}={fqdn1} {ip2}={fqdn2} ...` for every detected IP address (IPv4/IPv6).

- **JSON Log Line Support:**  
If `json_mode: true`, each log line is considered to be a well formed json fragement, so if `enrich_ip: true`, then the json fragment gains a sub-fragement inserted at the end as per  `"_resolv_": "{\"ip0\": \"fqdn0\", \"ip1\": \"fqdn1\",  \"ip2\": \"fqdn2\", ...} ` for every detected IP address (IPv4/IPv6).

- **File Aging:**  
Files in the queue are deleted if:
 - They are older than `queue_time_limit_days`
 - The total size of the queue exceeds `queue_size_limit_mb` (oldest files deleted first)
 - Defaults are set in the defaults configuration item

- **Execution Logging:**  
All script activity is logged in ISO8601 localtime format to standard output.

- **Custom timestamp regexes:**
These `regex, format` pairs offer a means of capturing the log's timestamp in a regex capture group, and having the contents of the capture group being passed to the strptime() routine along with the format to correctly interpret that log's timestamp. A special `format` of `epoch` is used when the timestamp is a Unix epoch time value.

---

## How Host Nameservers Are Discovered

The script collects the host's nameservers using multiple mechanisms:

1. **Parse `/etc/resolv.conf`**
2. **Query `nmcli`** (if available)
3. **Query `systemd-resolve` or `resolvectl`** (if available)
4. **Use dnspython's resolver** (if installed)
5. **Deduplication:** All discovered nameservers are merged and deduplicated.

---

## Example Cron Entry

To run the script every 5 minutes:

*/5 * * * * /usr/bin/python3 /opt/stroom/stroom_log_collector/stroom_log_collector/stroom_log_collector.py --config /opt/stroom/stroom_log_collector/config.yaml --state-dir /opt/stroom/stroom_log_collector/state --queue-dir /opt/stroom/stroom_log_collector/queue > /var/log/stroom_log_collector.log 2>&1

---

## Example 1

Consider the log file(s) produced by the [stroom-community-linuxauditd-agent](https://github.com/burnalting/stroom-community-linuxauditd-agent). A standard deployment may result in the following log files being present in `/var/log`, where we see the current log file and rolled over compressed log files.

```
/var/log/stroom_auditd_auditing.log
/var/log/stroom_auditd_auditing.log-20250707.gz
/var/log/stroom_auditd_auditing.log-20250708.gz
/var/log/stroom_auditd_auditing.log-20250709.gz
/var/log/stroom_auditd_auditing.log-20250710.gz
/var/log/stroom_auditd_auditing.log-20250711.gz
/var/log/stroom_auditd_auditing.log-20250712.gz
/var/log/stroom_auditd_auditing.log-20250713.gz
```

The file `/var/log/stroom_auditd_auditing.log` contains entries like

```
...
2025-07-13T03:20:01.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Obtained lock for 147239 in /usr/security/auditd/locks/stroom_auditd_feeder.sh.lck
2025-07-13T03:20:01.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Disconnect package directory, /usr/security/auditd/disconnected, was empty. No files processed
2025-07-13T03:20:01.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Removed lock /usr/security/auditd/locks/stroom_auditd_feeder.sh.lck for 147239
2025-07-13T03:30:01.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Obtained lock for 147410 in /usr/security/auditd/locks/stroom_auditd_feeder.sh.lck
2025-07-13T03:30:01.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Start gathering audit into /usr/security/auditd/queue/auditdProcessed.147410.1752341401.gz
2025-07-13T03:30:02.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Removed lock /usr/security/auditd/locks/stroom_auditd_feeder.sh.lck for 147410
2025-07-13T03:40:01.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Obtained lock for 147591 in /usr/security/auditd/locks/stroom_auditd_feeder.sh.lck
2025-07-13T03:40:01.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Disconnect package working directory, /usr/security/auditd/disconnected/_working, is not empty. Cannot remove
2025-07-13T03:40:01.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Send status: [200] SUCCESS  Audit Log: ./auditdProcessed.147066.1752340501.gz Size: 4.0K ProcessTime: 0 Feed: LINUX-AUDITD-AUSEARCH-V3-EVENTS URL: https://v7stroom-proxy.somedomain.org/stroom/datafeed
2025-07-13T03:40:01.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Removed lock /usr/security/auditd/locks/stroom_auditd_feeder.sh.lck for 147591
2025-07-13T03:45:01.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Obtained lock for 147710 in /usr/security/auditd/locks/stroom_auditd_feeder.sh.lck
2025-07-13T03:45:01.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Start gathering audit into /usr/security/auditd/queue/auditdProcessed.147710.1752342301.gz
2025-07-13T03:45:01.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Removed lock /usr/security/auditd/locks/stroom_auditd_feeder.sh.lck for 147710
2025-07-13T03:50:01.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Obtained lock for 147818 in /usr/security/auditd/locks/stroom_auditd_feeder.sh.lck
2025-07-13T03:50:01.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Disconnect package directory, /usr/security/auditd/disconnected, was empty. No files processed
2025-07-13T03:50:01.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Removed lock /usr/security/auditd/locks/stroom_auditd_feeder.sh.lck for 147818
2025-07-13T04:00:02.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Obtained lock for 147988 in /usr/security/auditd/locks/stroom_auditd_feeder.sh.lck
2025-07-13T04:00:02.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Start gathering audit into /usr/security/auditd/queue/auditdProcessed.147988.1752343202.gz
2025-07-13T04:00:02.000+10:00 stroom_auditd_feeder.sh swtf.somedomain.org: Removed lock /usr/security/auditd/locks/stroom_auditd_feeder.sh.lck for 147988

```

A configuration file to monitor and post events to a stroom proxy for these logs might look like

```
# Main list of Stroom proxy endpoints to post logs to (failover order)
stroom_proxies:
  - https://v7stroom-proxy.somedomain.org/stroom/datafeed

# TLS/SSL configuration for HTTPS requests
tls:
  ca_cert: "false"                       # (string "false" disables verification, not recommended for production)

# Default timeout (in seconds) for posting logs to proxies
timeout_seconds: 10

# List of log sources ("feeds") to monitor and post
feeds:
  - name: StroomAuditd                                   # Unique identifier for this feed (used in state file)
    log_pattern: /var/log/stroom_auditd_auditing.log*    # Glob pattern for log files (rotated and base)
    feed_name: STROOM_AUDIT_AGENT-V1.0-EVENTS            # Stroom feed name to use in HTTP header
    headers:                             # (Optional) Additional HTTP headers for this feed
      Environment: Production
      LogType: Stroom Agent
    custom_formats:                      # (Optional) List of custom timestamp regex/format pairs
      - regex: '^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+(?:Z|[+-]\d{2}:?\d{2}))'
        format: '%Y-%m-%dT%H:%M:%S.%f%z' # For 2025-07-07T07:45:02.000+10:00
    enrich_ip: false                      # (Optional) If true, append FQDNs for all IPs in each line
    queue_time_limit_days: 7             # (Optional) Max age (days) for queued files for this feed
    queue_size_limit_mb: 500             # (Optional) Max queue size (MB) for this feed
    timeout_seconds: 20                  # (Optional) Override global timeout for this feed

# Default retention/queue settings (used if not overridden per-feed)
defaults:
  queue_time_limit_days: 14        # Max age (days) for queued files
  queue_size_limit_mb: 1024        # Max total size (MB) for queued files
```

The first execution may show

```
# ./stroom_log_collector.py --config stroom_log_collector.yml --state-dir state --queue-dir queue --debug
2025-07-13T17:17:31.985+1000 INFO Log Collector started with config: stroom_log_collector_swtf.yml, state_dir: state, queue_dir: queue
2025-07-13T17:17:31.998+1000 INFO Post summary for feed 'STROOM_AUDIT_AGENT-V1.0-EVENTS': 0 succeeded, 0 failed.
2025-07-13T17:17:31.998+1000 INFO Processing log files in order: /var/log/stroom_auditd_auditing.log-20250707.gz, /var/log/stroom_auditd_auditing.log-20250708.gz, /var/log/stroom_auditd_auditing.log-20250709.gz, /var/log/stroom_auditd_auditing.log-20250710.gz, /var/log/stroom_auditd_auditing.log-20250711.gz, /var/log/stroom_auditd_auditing.log-20250712.gz, /var/log/stroom_auditd_auditing.log-20250713.gz, /var/log/stroom_auditd_auditing.log
2025-07-13T17:17:31.999+1000 DEBUG Processing /var/log/stroom_auditd_auditing.log-20250707.gz
2025-07-13T17:17:33.380+1000 DEBUG Processing /var/log/stroom_auditd_auditing.log-20250708.gz
2025-07-13T17:17:33.390+1000 DEBUG Processing /var/log/stroom_auditd_auditing.log-20250709.gz
2025-07-13T17:17:33.414+1000 DEBUG Processing /var/log/stroom_auditd_auditing.log-20250710.gz
2025-07-13T17:17:33.427+1000 DEBUG Processing /var/log/stroom_auditd_auditing.log-20250711.gz
2025-07-13T17:17:33.437+1000 DEBUG Processing /var/log/stroom_auditd_auditing.log-20250712.gz
2025-07-13T17:17:33.449+1000 DEBUG Processing /var/log/stroom_auditd_auditing.log-20250713.gz
2025-07-13T17:17:33.462+1000 DEBUG Processing /var/log/stroom_auditd_auditing.log
2025-07-13T17:17:33.842+1000 INFO Queued new file queue/STROOM_AUDIT_AGENT-V1.0-EVENTS_20250713_171501+1000.log.gz for feed STROOM_AUDIT_AGENT-V1.0-EVENTS
2025-07-13T17:17:33.880+1000 DEBUG Starting new HTTPS connection (1): v7stroom-proxy.somedomain.org:443
2025-07-13T17:17:34.265+1000 DEBUG https://v7stroom-proxy.somedomain.org:443 "POST /stroom/datafeed HTTP/1.1" 200 None
2025-07-13T17:17:34.267+1000 INFO Posted file queue/STROOM_AUDIT_AGENT-V1.0-EVENTS_20250713_171501+1000.log.gz to https://v7stroom-proxy.somedomain.org/stroom/datafeed
2025-07-13T17:17:34.268+1000 INFO Successfully posted and removed file: queue/STROOM_AUDIT_AGENT-V1.0-EVENTS_20250713_171501+1000.log.gz
2025-07-13T17:17:34.268+1000 INFO Post summary for feed 'STROOM_AUDIT_AGENT-V1.0-EVENTS': 1 succeeded, 0 failed.
2025-07-13T17:17:34.269+1000 INFO Age-out summary: 0 files deleted for age, 0 files deleted for size, 0 files remain.
2025-07-13T17:17:34.270+1000 INFO Log Collector finished.
# 
```

Running the script again, before additional data is in `/var/log/stroom_auditd_auditding.log`, would show

```
# ./stroom_log_collector.py --config stroom_log_collector_swtf.yml --state-dir state --queue-dir queue --debug
2025-07-13T17:18:20.344+1000 INFO Log Collector started with config: stroom_log_collector_swtf.yml, state_dir: state, queue_dir: queue
2025-07-13T17:18:20.362+1000 INFO Post summary for feed 'STROOM_AUDIT_AGENT-V1.0-EVENTS': 0 succeeded, 0 failed.
2025-07-13T17:18:20.364+1000 INFO Processing log files in order: /var/log/stroom_auditd_auditing.log-20250707.gz, /var/log/stroom_auditd_auditing.log-20250708.gz, /var/log/stroom_auditd_auditing.log-20250709.gz, /var/log/stroom_auditd_auditing.log-20250710.gz, /var/log/stroom_auditd_auditing.log-20250711.gz, /var/log/stroom_auditd_auditing.log-20250712.gz, /var/log/stroom_auditd_auditing.log-20250713.gz, /var/log/stroom_auditd_auditing.log
2025-07-13T17:18:20.364+1000 DEBUG Skipping /var/log/stroom_auditd_auditing.log-20250707.gz (mtime 1751822401.0 <= last_ts 1752391202.0)
2025-07-13T17:18:20.364+1000 DEBUG Skipping /var/log/stroom_auditd_auditing.log-20250708.gz (mtime 1751910001.0 <= last_ts 1752391202.0)
2025-07-13T17:18:20.364+1000 DEBUG Skipping /var/log/stroom_auditd_auditing.log-20250709.gz (mtime 1751994901.0 <= last_ts 1752391202.0)
2025-07-13T17:18:20.364+1000 DEBUG Skipping /var/log/stroom_auditd_auditing.log-20250710.gz (mtime 1752099001.0 <= last_ts 1752391202.0)
2025-07-13T17:18:20.364+1000 DEBUG Skipping /var/log/stroom_auditd_auditing.log-20250711.gz (mtime 1752167702.0 <= last_ts 1752391202.0)
2025-07-13T17:18:20.364+1000 DEBUG Skipping /var/log/stroom_auditd_auditing.log-20250712.gz (mtime 1752253201.0 <= last_ts 1752391202.0)
2025-07-13T17:18:20.364+1000 DEBUG Skipping /var/log/stroom_auditd_auditing.log-20250713.gz (mtime 1752340501.0 <= last_ts 1752391202.0)
2025-07-13T17:18:20.364+1000 DEBUG Processing /var/log/stroom_auditd_auditing.log
2025-07-13T17:18:20.369+1000 INFO Age-out summary: 0 files deleted for age, 0 files deleted for size, 0 files remain.
2025-07-13T17:18:20.369+1000 INFO Log Collector finished
#
```
But if we wait, we see

```
# ./stroom_log_collector.py --config stroom_log_collector_swtf.yml --state-dir state --queue-dir queue --debug
2025-07-13T17:21:36.547+1000 INFO Log Collector started with config: stroom_log_collector_swtf.yml, state_dir: state, queue_dir: queue
2025-07-13T17:21:36.560+1000 INFO Post summary for feed 'STROOM_AUDIT_AGENT-V1.0-EVENTS': 0 succeeded, 0 failed.
2025-07-13T17:21:36.564+1000 INFO Processing log files in order: /var/log/stroom_auditd_auditing.log-20250707.gz, /var/log/stroom_auditd_auditing.log-20250708.gz, /var/log/stroom_auditd_auditing.log-20250709.gz, /var/log/stroom_auditd_auditing.log-20250710.gz, /var/log/stroom_auditd_auditing.log-20250711.gz, /var/log/stroom_auditd_auditing.log-20250712.gz, /var/log/stroom_auditd_auditing.log-20250713.gz, /var/log/stroom_auditd_auditing.log
2025-07-13T17:21:36.565+1000 DEBUG Skipping /var/log/stroom_auditd_auditing.log-20250707.gz (mtime 1751822401.0 <= last_ts 1752390901.0)
2025-07-13T17:21:36.565+1000 DEBUG Skipping /var/log/stroom_auditd_auditing.log-20250708.gz (mtime 1751910001.0 <= last_ts 1752390901.0)
2025-07-13T17:21:36.565+1000 DEBUG Skipping /var/log/stroom_auditd_auditing.log-20250709.gz (mtime 1751994901.0 <= last_ts 1752390901.0)
2025-07-13T17:21:36.565+1000 DEBUG Skipping /var/log/stroom_auditd_auditing.log-20250710.gz (mtime 1752099001.0 <= last_ts 1752390901.0)
2025-07-13T17:21:36.565+1000 DEBUG Skipping /var/log/stroom_auditd_auditing.log-20250711.gz (mtime 1752167702.0 <= last_ts 1752390901.0)
2025-07-13T17:21:36.565+1000 DEBUG Skipping /var/log/stroom_auditd_auditing.log-20250712.gz (mtime 1752253201.0 <= last_ts 1752390901.0)
2025-07-13T17:21:36.565+1000 DEBUG Skipping /var/log/stroom_auditd_auditing.log-20250713.gz (mtime 1752340501.0 <= last_ts 1752390901.0)
2025-07-13T17:21:36.565+1000 DEBUG Processing /var/log/stroom_auditd_auditing.log
2025-07-13T17:21:36.572+1000 INFO Queued new file queue/STROOM_AUDIT_AGENT-V1.0-EVENTS_20250713_172002+1000.log.gz for feed STROOM_AUDIT_AGENT-V1.0-EVENTS
2025-07-13T17:21:36.574+1000 DEBUG Starting new HTTPS connection (1): v7stroom-proxy.somedomain.org:443
2025-07-13T17:21:36.615+1000 DEBUG https://v7stroom-proxy.somedomain.org:443 "POST /stroom/datafeed HTTP/1.1" 200 None
2025-07-13T17:21:36.617+1000 INFO Posted file queue/STROOM_AUDIT_AGENT-V1.0-EVENTS_20250713_172002+1000.log.gz to https://v7stroom-proxy.somedomain.org/stroom/datafeed
2025-07-13T17:21:36.617+1000 INFO Successfully posted and removed file: queue/STROOM_AUDIT_AGENT-V1.0-EVENTS_20250713_172002+1000.log.gz
2025-07-13T17:21:36.618+1000 INFO Post summary for feed 'STROOM_AUDIT_AGENT-V1.0-EVENTS': 1 succeeded, 0 failed.
2025-07-13T17:21:36.618+1000 INFO Age-out summary: 0 files deleted for age, 0 files deleted for size, 0 files remain.
2025-07-13T17:21:36.618+1000 INFO Log Collector finished.
#
```

## Example 2

In this example, we want to monitor an [Nginx](https://nginx.org) system's access and error log where the access log has been configured to use the Nginx blackboxSSLUser logging format. This format is configured as per

```
log_format blackboxSSLUser
  '$remote_addr $remote_addr/$remote_port - '
  '[$time_iso8601] - '
  '"$ssl_client_s_dn" "$request" $status '
  '$request_time $request_length/$bytes_sent/$body_bytes_sent '
  '"$http_referer" "$http_user_agent" $server_name/$server_port "$is_args$request_uri"';
access_log /var/log/nginx/blackbox_ssl_user.log blackboxSSLUser;
```

So our configuration file for this might look like

```
# Main list of Stroom proxy endpoints to post logs to (failover order)
stroom_proxies:
  - https://v7stroom-proxy.somedomain.org/stroom/datafeed

# TLS/SSL configuration for HTTPS requests
tls:
  ca_cert: "false"                       # (string "false" disables verification, not recommended for production)

# Default timeout (in seconds) for posting logs to proxies
timeout_seconds: 10

# List of log sources ("feeds") to monitor and post
feeds:
  - name: StroomNginx-Access                            # Unique identifier for this feed (used in state file)
    log_pattern: /var/log/nginx/blackbox_ssl_user.log*  # Glob pattern for log files (rotated and base)
    feed_name: NginxAccess-BlackBox-V1.0-EVENTS         # Stroom feed name to use in HTTP header
    headers:                             # (Optional) Additional HTTP headers for this feed
      Environment: Production
      LogType: Nginx Access for capabilty XXX
    custom_formats:                      # (Optional) List of custom timestamp regex/format pairs
      - regex: '\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})\]'
        format: '%Y-%m-%dT%H:%M:%S%z'  # For 2025-07-12T10:16:37+10:00
      - regex: '\[(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]'
        format: '%d/%b/%Y:%H:%M:%S %z' # For 12/Jul/2025:03:24:53 +0000
    enrich_ip: true                      # (Optional) If true, append FQDNs for all IPs in each line
    queue_time_limit_days: 7             # (Optional) Max age (days) for queued files for this feed
    queue_size_limit_mb: 500             # (Optional) Max queue size (MB) for this feed
    timeout_seconds: 20                  # (Optional) Override global timeout for this feed

  - name: StroomNginx-Error              # Unique identifier for this feed (used in state file)
    log_pattern: /var/log/nginx/error.log*  # Glob pattern for log files (rotated and base)
    feed_name: NginxError-Standard-V1.0-EVENTS         # Stroom feed name to use in HTTP header
    headers:                             # (Optional) Additional HTTP headers for this feed
      Environment: Production
      LogType: Nginx Error log for capabilty XXX
    custom_formats:                      # (Optional) List of custom timestamp regex/format pairs
      - regex: '(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'
        format: '%Y/%m/%d %H:%M:%S' # For 2025/07/16 10:03:39
    enrich_ip: true                      # (Optional) If true, append FQDNs for all IPs in each line
    queue_time_limit_days: 7             # (Optional) Max age (days) for queued files for this feed
    queue_size_limit_mb: 500             # (Optional) Max queue size (MB) for this feed

# Default retention/queue settings (used if not overridden per-feed)
defaults:
  queue_time_limit_days: 14        # Max age (days) for queued files
  queue_size_limit_mb: 1024        # Max total size (MB) for queued files
```

We will use some sample Nginx access logs generated from the internet

```
8.8.8.8 8.8.8.8/53125 - [2025-07-16T10:01:15+00:00] - "/C=US/ST=CA/CN=client1.example.com" "GET /index.html HTTP/1.1" 200 0.123 512/1024/512 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" example.com/443 "/index.html"
192.0.2.43 192.0.2.43/42022 - [2025-07-16T10:01:45+00:00] - "" "POST /api/data HTTP/1.1" 201 0.308 951/2048/2041 "https://example.com/form" "curl/7.85.0" api.example.net/443 "/api/data"
198.51.100.17 198.51.100.17/41234 - [2025-07-16T10:02:07+00:00] - "/C=US/CN=unknown" "GET /image.png HTTP/1.1" 304 0.056 211/0/0 "https://img.example.com" "Mozilla/5.0 (X11; Linux x86_64)" cdn.example.org/443 "/image.png"
172.16.0.24 172.16.0.24/53782 - [2025-07-16T10:02:31+00:00] - "" "GET /private/dashboard HTTP/1.1" 403 0.201 1435/2500/1500 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" dashboard.local/443 "/private/dashboard"
45.33.32.156 45.33.32.156/61612 - [2025-07-16T10:03:01+00:00] - "/C=DE/L=Berlin/CN=user.de" "GET /shop HTTP/1.1" 200 0.099 650/800/800 "https://referer.example" "Mozilla/5.0 (Android 12; Mobile)" shop.example.com/443 "/shop"
10.0.0.5 10.0.0.5/61001 - [2025-07-16T10:03:27+00:00] - "" "GET /internal/ping HTTP/1.1" 200 0.005 60/100/100 "-" "curl/8.1.2" internal.example.local/443 "/internal/ping"
203.0.113.7 203.0.113.7/50211 - [2025-07-16T10:04:03+00:00] - "/C=CA/CN=cdn.ca" "GET /asset.js HTTP/1.1" 200 0.087 340/512/512 "https://example.ca" "Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X)" cdn.ca.net/443 "/asset.js"
2606:4700:4700::1111 2606:4700:4700::1111/55443 - [2025-07-16T10:04:41+00:00] - "" "GET /dns-query HTTP/2" 200 0.074 128/280/280 "-" "DoH Client/1.3" cloudflare-dns.com/443 "/dns-query"
93.184.216.34 93.184.216.34/61423 - [2025-07-16T10:05:19+00:00] - "/C=US/CN=example.com" "GET /about HTTP/1.1" 200 0.113 412/600/600 "https://example.com" "Mozilla/5.0 (Windows NT 11.0)" site.example.com/443 "/about"
fd00::abcd fd00::abcd/51515 - [2025-07-16T10:05:57+00:00] - "" "GET /metrics HTTP/1.1" 200 0.032 123/256/256 "-" "Prometheus/2.42.1" metrics.internal/443 "/metrics"
```

And error log of

```
2025/07/16 10:01:42 [error] 1234#0: *101 SSL_do_handshake() failed (SSL: error:14094410:SSL routines:ssl3_read_bytes:sslv3 alert handshake failure) while SSL handshaking, client: 192.0.2.43, server: 0.0.0.0:443
2025/07/16 10:02:01 [warn] 1234#0: *102 no If-Modified-Since header in conditional GET request for /static/img/logo.png, client: 198.51.100.17, server: cdn.example.org
2025/07/16 10:02:24 [error] 1234#0: *103 open() "/var/www/html/robots.txt" failed (2: No such file or directory), client: 203.0.113.7, server: site.example.com
2025/07/16 10:03:18 [notice] 1234#0: signal process started
2025/07/16 10:03:39 [error] 1234#0: *104 connect() failed (111: Connection refused) while connecting to upstream, client: 172.16.0.24, server: api.example.net, request: "GET /api/status HTTP/1.1", upstream: "http://127.0.0.1:8081/status"
2025/07/16 10:04:02 [crit] 1234#0: *105 SSL_write() failed (SSL: syscall failure: Broken pipe) while sending to client, client: 10.0.0.5, server: internal.example.local
2025/07/16 10:04:26 [error] 1234#0: *106 invalid host in upstream "http://:8080", client: 45.33.32.156, server: example.com, request: "GET /services HTTP/1.1"
2025/07/16 10:04:59 [warn] 1234#0: *107 using uninitialized variable "$custom_var" while logging request, client: 93.184.216.34, server: shop.example.com
2025/07/16 10:05:13 [error] 1234#0: *108 client intended to send too large body: 10485760 bytes, client: 2606:4700:4700::1111, server: cdn.ca.net, request: "POST /upload HTTP/1.1"
```

So we now execute with debug and test mode, so we don't post the file to the configured stroom proxy (as we want to see the effect
of resolving ip addresses)


```
# ./stroom_log_collector.py --config stroom_log_collector_nginx.yml --state-dir nstate --queue-dir nqueue --debug --test
2025-07-19T13:33:38.844+1000 INFO Log Collector started with config: stroom_log_collector_nginx.yml, state_dir: nstate, queue_dir: nqueue
2025-07-19T13:33:38.859+1000 INFO Post summary for feed 'NginxAccess-BlackBox-V1.0-EVENTS': 0 succeeded, 0 failed.
2025-07-19T13:33:38.861+1000 INFO Processing log files in order: /var/log/nginx/blackbox_ssl_user.log
2025-07-19T13:33:38.861+1000 DEBUG Processing /var/log/nginx/blackbox_ssl_user.log
2025-07-19T13:33:38.972+1000 DEBUG socket.gethostbyaddr('192.0.2.43') failed: [Errno 1] Unknown host
2025-07-19T13:33:38.976+1000 DEBUG socket.gethostbyaddr('198.51.100.17') failed: [Errno 1] Unknown host
2025-07-19T13:33:38.979+1000 DEBUG socket.gethostbyaddr('172.16.0.24') failed: [Errno 1] Unknown host
2025-07-19T13:33:39.870+1000 DEBUG socket.gethostbyaddr('10.0.0.5') failed: [Errno 1] Unknown host
2025-07-19T13:33:39.875+1000 DEBUG socket.gethostbyaddr('203.0.113.7') failed: [Errno 1] Unknown host
2025-07-19T13:33:40.776+1000 DEBUG socket.gethostbyaddr('93.184.216.34') failed: [Errno 1] Unknown host
2025-07-19T13:33:40.781+1000 DEBUG socket.gethostbyaddr('fd00::abcd') failed: [Errno 1] Unknown host
2025-07-19T13:33:40.784+1000 INFO Queued new file nqueue/NginxAccess-BlackBox-V1.0-EVENTS_20250716_100557+0000.log.gz for feed NginxAccess-BlackBox-V1.0-EVENTS
2025-07-19T13:33:40.784+1000 INFO [TEST MODE] Would post file nqueue/NginxAccess-BlackBox-V1.0-EVENTS_20250716_100557+0000.log.gz to proxies: ['https://v7stroom-proxy.somedomain.org/stroom/datafeed']
2025-07-19T13:33:40.784+1000 INFO [TEST MODE] with headers Environment: Production; LogType: Nginx Access for capabilty XXX; MyIPAddresses: 192.168.1.107,192.168.122.1,fe80:0000:0000:0000:0a00:27ff:fe1a:b7a9; MyHosts: 192.168.1.107,192.168.122.1,fe80::a00:27ff:fe1a:b7a9,swtf.somedomain.org; MyNameServer: 192.168.1.1; Feed: NginxAccess-BlackBox-V1.0-EVENTS; Compression: GZIP; TZ: Australia/Sydney
2025-07-19T13:33:40.784+1000 INFO Successfully posted and removed file: nqueue/NginxAccess-BlackBox-V1.0-EVENTS_20250716_100557+0000.log.gz
2025-07-19T13:33:40.785+1000 INFO Post summary for feed 'NginxAccess-BlackBox-V1.0-EVENTS': 1 succeeded, 0 failed.
2025-07-19T13:33:40.785+1000 INFO Age-out summary: 0 files deleted for age, 0 files deleted for size, 1 files remain.
2025-07-19T13:33:40.786+1000 INFO Post summary for feed 'NginxError-Standard-V1.0-EVENTS': 0 succeeded, 0 failed.
2025-07-19T13:33:40.788+1000 INFO Processing log files in order: /var/log/nginx/error.log
2025-07-19T13:33:40.788+1000 DEBUG Processing /var/log/nginx/error.log
2025-07-19T13:33:40.792+1000 DEBUG socket.gethostbyaddr('0.0.0.0') failed: [Errno 1] Unknown host
2025-07-19T13:33:40.795+1000 DEBUG socket.gethostbyaddr('192.0.2.43') failed: [Errno 1] Unknown host
2025-07-19T13:33:40.800+1000 DEBUG socket.gethostbyaddr('198.51.100.17') failed: [Errno 1] Unknown host
2025-07-19T13:33:40.813+1000 DEBUG socket.gethostbyaddr('203.0.113.7') failed: [Errno 1] Unknown host
2025-07-19T13:33:40.817+1000 DEBUG socket.gethostbyaddr('172.16.0.24') failed: [Errno 1] Unknown host
2025-07-19T13:33:40.826+1000 DEBUG socket.gethostbyaddr('10.0.0.5') failed: [Errno 1] Unknown host
2025-07-19T13:33:40.833+1000 DEBUG socket.gethostbyaddr('93.184.216.34') failed: [Errno 1] Unknown host
2025-07-19T13:33:40.837+1000 INFO Queued new file nqueue/NginxError-Standard-V1.0-EVENTS_20250716_100600.log.gz for feed NginxError-Standard-V1.0-EVENTS
2025-07-19T13:33:40.838+1000 INFO [TEST MODE] Would post file nqueue/NginxError-Standard-V1.0-EVENTS_20250716_100600.log.gz to proxies: ['https://v7stroom-proxy.somedomain.org/stroom/datafeed']
2025-07-19T13:33:40.838+1000 INFO [TEST MODE] with headers Environment: Production; LogType: Nginx Error LOg for capabilty XXX; MyIPAddresses: 192.168.1.107,192.168.122.1,fe80:0000:0000:0000:0a00:27ff:fe1a:b7a9; MyHosts: 192.168.1.107,192.168.122.1,fe80::a00:27ff:fe1a:b7a9,swtf.somedomain.org; MyNameServer: 192.168.1.1; Feed: NginxError-Standard-V1.0-EVENTS; Compression: GZIP; TZ: Australia/Sydney
2025-07-19T13:33:40.838+1000 INFO Successfully posted and removed file: nqueue/NginxError-Standard-V1.0-EVENTS_20250716_100600.log.gz
2025-07-19T13:33:40.838+1000 INFO Post summary for feed 'NginxError-Standard-V1.0-EVENTS': 1 succeeded, 0 failed.
2025-07-19T13:33:40.838+1000 INFO Age-out summary: 0 files deleted for age, 0 files deleted for size, 2 files remain.
2025-07-19T13:33:40.838+1000 INFO Log Collector finished.
# 
```

And if we look at the queued files, we see some of the ip addresses identifed and, if possible, resolved

```
# gunzip -c nqueue/NginxAccess-BlackBox-V1.0-EVENTS_20250716_100557+0000.log.gz
8.8.8.8 8.8.8.8/53125 - [2025-07-16T10:01:15+00:00] - "/C=US/ST=CA/CN=client1.example.com" "GET /index.html HTTP/1.1" 200 0.123 512/1024/512 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" example.com/443 "/index.html" _resolv_: 8.8.8.8=dns.google
192.0.2.43 192.0.2.43/42022 - [2025-07-16T10:01:45+00:00] - "" "POST /api/data HTTP/1.1" 201 0.308 951/2048/2041 "https://example.com/form" "curl/7.85.0" api.example.net/443 "/api/data" _resolv_: 192.0.2.43=-
198.51.100.17 198.51.100.17/41234 - [2025-07-16T10:02:07+00:00] - "/C=US/CN=unknown" "GET /image.png HTTP/1.1" 304 0.056 211/0/0 "https://img.example.com" "Mozilla/5.0 (X11; Linux x86_64)" cdn.example.org/443 "/image.png" _resolv_: 198.51.100.17=-
172.16.0.24 172.16.0.24/53782 - [2025-07-16T10:02:31+00:00] - "" "GET /private/dashboard HTTP/1.1" 403 0.201 1435/2500/1500 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" dashboard.local/443 "/private/dashboard" _resolv_: 172.16.0.24=-
45.33.32.156 45.33.32.156/61612 - [2025-07-16T10:03:01+00:00] - "/C=DE/L=Berlin/CN=user.de" "GET /shop HTTP/1.1" 200 0.099 650/800/800 "https://referer.example" "Mozilla/5.0 (Android 12; Mobile)" shop.example.com/443 "/shop" _resolv_: 45.33.32.156=scanme.nmap.org
10.0.0.5 10.0.0.5/61001 - [2025-07-16T10:03:27+00:00] - "" "GET /internal/ping HTTP/1.1" 200 0.005 60/100/100 "-" "curl/8.1.2" internal.example.local/443 "/internal/ping" _resolv_: 10.0.0.5=-
203.0.113.7 203.0.113.7/50211 - [2025-07-16T10:04:03+00:00] - "/C=CA/CN=cdn.ca" "GET /asset.js HTTP/1.1" 200 0.087 340/512/512 "https://example.ca" "Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X)" cdn.ca.net/443 "/asset.js" _resolv_: 203.0.113.7=-
2606:4700:4700::1111 2606:4700:4700::1111/55443 - [2025-07-16T10:04:41+00:00] - "" "GET /dns-query HTTP/2" 200 0.074 128/280/280 "-" "DoH Client/1.3" cloudflare-dns.com/443 "/dns-query" _resolv_: 2606:4700:4700::1111=one.one.one.one
93.184.216.34 93.184.216.34/61423 - [2025-07-16T10:05:19+00:00] - "/C=US/CN=example.com" "GET /about HTTP/1.1" 200 0.113 412/600/600 "https://example.com" "Mozilla/5.0 (Windows NT 11.0)" site.example.com/443 "/about" _resolv_: 93.184.216.34=-
fd00::abcd fd00::abcd/51515 - [2025-07-16T10:05:57+00:00] - "" "GET /metrics HTTP/1.1" 200 0.032 123/256/256 "-" "Prometheus/2.42.1" metrics.internal/443 "/metrics" _resolv_: fd00::abcd=-
# 
```

```
# gunzip -c nqueue/NginxError-Standard-V1.0-EVENTS_20250716_100600.log.gz
2025/07/16 10:01:42 [error] 1234#0: *101 SSL_do_handshake() failed (SSL: error:14094410:SSL routines:ssl3_read_bytes:sslv3 alert handshake failure) while SSL handshaking, client: 192.0.2.43, server: 0.0.0.0:443 _resolv_: 0.0.0.0=- 192.0.2.43=-
2025/07/16 10:02:01 [warn] 1234#0: *102 no If-Modified-Since header in conditional GET request for /static/img/logo.png, client: 198.51.100.17, server: cdn.example.org _resolv_: 198.51.100.17=-
2025/07/16 10:02:24 [error] 1234#0: *103 open() "/var/www/html/robots.txt" failed (2: No such file or directory), client: 203.0.113.7, server: site.example.com _resolv_: 203.0.113.7=-
2025/07/16 10:03:18 [notice] 1234#0: signal process started
2025/07/16 10:03:39 [error] 1234#0: *104 connect() failed (111: Connection refused) while connecting to upstream, client: 172.16.0.24, server: api.example.net, request: "GET /api/status HTTP/1.1", upstream: "http://127.0.0.1:8081/status" _resolv_: 127.0.0.1=localhost 172.16.0.24=-
2025/07/16 10:04:02 [crit] 1234#0: *105 SSL_write() failed (SSL: syscall failure: Broken pipe) while sending to client, client: 10.0.0.5, server: internal.example.local _resolv_: 10.0.0.5=-
2025/07/16 10:04:26 [error] 1234#0: *106 invalid host in upstream "http://:8080", client: 45.33.32.156, server: example.com, request: "GET /services HTTP/1.1" _resolv_: 45.33.32.156=scanme.nmap.org
2025/07/16 10:04:59 [warn] 1234#0: *107 using uninitialized variable "$custom_var" while logging request, client: 93.184.216.34, server: shop.example.com _resolv_: 93.184.216.34=-
2025/07/16 10:05:13 [error] 1234#0: *108 client intended to send too large body: 10485760 bytes, client: 2606:4700:4700::1111, server: cdn.ca.net, request: "POST /upload HTTP/1.1" _resolv_: 2606:4700:4700::1111=one.one.one.one
2025/07/16 10:06:00 [notice] 1234#0: signal 1 (SIGHUP) received, reconfiguring
# 
```

And if we looked at the state files we would see the last line's timestamp of each source log file as per the following.

```
# cat nstate/NginxAccess-BlackBox-V1.0-EVENTS.json
{"last_timestamp": "2025-07-16T10:04:41.000000+0000"}#
# cat nstate/NginxError-Standard-V1.0-EVENTS.json
{"last_timestamp": "2025-07-16T10:06:00.000000"}#
```

Note that the # on the end of each json fragment is the command line prompt as these fragments are not newline terminated. Further, the absence of a timezone for the Nginx Error log is a result of a Nginx error log has a fixed timestamp and set to the server's local timezone.

## Example 3

In this example, we want to monitor an [Nginx](https://nginx.org) system's access log where the access log has been configured to use the Nginx blackboxSSLUser logging format in json. This format is configured as per

```
log_format blackboxSSLUser escape=json '{'
  '"remote_addr":"$remote_addr",'
  '"remote_port":"$remote_port",'
  '"time_iso8601":"$time_iso8601",'
  '"ssl_client_s_dn":"$ssl_client_s_dn",'
  '"request":"$request",'
  '"status":$status,'
  '"request_time":$request_time,'
  '"request_length":$request_length,'
  '"bytes_sent":$bytes_sent,'
  '"body_bytes_sent":$body_bytes_sent,'
  '"http_referer":"$http_referer",'
  '"http_user_agent":"$http_user_agent",'
  '"server_name":"$server_name",'
  '"server_port":"$server_port",'
  '"uri":"$uri"
'}';
access_log /var/log/nginx/blackbox_ssl_user.log blackboxSSLUser;
```

So our configuration file for this might look like

```
# Main list of Stroom proxy endpoints to post logs to (failover order)
stroom_proxies:
  - https://v7stroom-proxy.somedomain.org/stroom/datafeed

# TLS/SSL configuration for HTTPS requests
tls:
  ca_cert: "false"                       # (string "false" disables verification, not recommended for production)

# Default timeout (in seconds) for posting logs to proxies
timeout_seconds: 10

# List of log sources ("feeds") to monitor and post
feeds:
  - name: StroomNginx-Access                            # Unique identifier for this feed (used in state file)
    log_pattern: /var/log/nginx/blackbox_ssl_user.log*  # Glob pattern for log files (rotated and base)
    feed_name: NginxAccess-BlackBox-V1.0-EVENTS         # Stroom feed name to use in HTTP header
    headers:                             # (Optional) Additional HTTP headers for this feed
      Environment: Production
      LogType: Nginx Access for capabilty XXX
    custom_formats:                      # (Optional) List of custom timestamp regex/format pairs
      - regex: '\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})\]'
        format: '%Y-%m-%dT%H:%M:%S%z'  # For 2025-07-12T10:16:37+10:00
      - regex: '\[(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]'
        format: '%d/%b/%Y:%H:%M:%S %z' # For 12/Jul/2025:03:24:53 +0000
    enrich_ip: true                      # (Optional) If true, append FQDNs for all IPs in each line
    json_mode: true                      # (Optional) If true, treat the input line as a json fragment
    queue_time_limit_days: 7             # (Optional) Max age (days) for queued files for this feed
    queue_size_limit_mb: 500             # (Optional) Max queue size (MB) for this feed
    timeout_seconds: 20                  # (Optional) Override global timeout for this feed

# Default retention/queue settings (used if not overridden per-feed)
defaults:
  queue_time_limit_days: 14        # Max age (days) for queued files
  queue_size_limit_mb: 1024        # Max total size (MB) for queued files
```

We will use some sample Nginx access logs generated from the internet

```
{"remote_addr":"8.8.8.8","remote_port":"53125","time_iso8601":"2025-07-16T10:01:15+00:00","ssl_client_s_dn":"/C=US/ST=CA/CN=client1.example.com","request":"GET /index.html HTTP/1.1","status":200,"request_time":0.123,"request_length":512,"bytes_sent":1024,"body_bytes_sent":512,"http_referer":"-","http_user_agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64)","server_name":"example.com","server_port":"443","uri":"/index.html"}
{"remote_addr":"192.0.2.43","remote_port":"42022","time_iso8601":"2025-07-16T10:01:45+00:00","ssl_client_s_dn":"","request":"POST /api/data HTTP/1.1","status":201,"request_time":0.308,"request_length":951,"bytes_sent":2048,"body_bytes_sent":2041,"http_referer":"https://example.com/form","http_user_agent":"curl/7.85.0","server_name":"api.example.net","server_port":"443","uri":"/api/data"}
{"remote_addr":"198.51.100.17","remote_port":"41234","time_iso8601":"2025-07-16T10:02:07+00:00","ssl_client_s_dn":"/C=US/CN=unknown","request":"GET /image.png HTTP/1.1","status":304,"request_time":0.056,"request_length":211,"bytes_sent":0,"body_bytes_sent":0,"http_referer":"https://img.example.com","http_user_agent":"Mozilla/5.0 (X11; Linux x86_64)","server_name":"cdn.example.org","server_port":"443","uri":"/image.png"}
{"remote_addr":"172.16.0.24","remote_port":"53782","time_iso8601":"2025-07-16T10:02:31+00:00","ssl_client_s_dn":"","request":"GET /private/dashboard HTTP/1.1","status":403,"request_time":0.201,"request_length":1435,"bytes_sent":2500,"body_bytes_sent":1500,"http_referer":"-","http_user_agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)","server_name":"dashboard.local","server_port":"443","uri":"/private/dashboard"}
{"remote_addr":"45.33.32.156","remote_port":"61612","time_iso8601":"2025-07-16T10:03:01+00:00","ssl_client_s_dn":"/C=DE/L=Berlin/CN=user.de","request":"GET /shop HTTP/1.1","status":200,"request_time":0.099,"request_length":650,"bytes_sent":800,"body_bytes_sent":800,"http_referer":"https://referer.example","http_user_agent":"Mozilla/5.0 (Android 12; Mobile)","server_name":"shop.example.com","server_port":"443","uri":"/shop"}
{"remote_addr":"10.0.0.5","remote_port":"61001","time_iso8601":"2025-07-16T10:03:27+00:00","ssl_client_s_dn":"","request":"GET /internal/ping HTTP/1.1","status":200,"request_time":0.005,"request_length":60,"bytes_sent":100,"body_bytes_sent":100,"http_referer":"-","http_user_agent":"curl/8.1.2","server_name":"internal.example.local","server_port":"443","uri":"/internal/ping"}
{"remote_addr":"203.0.113.7","remote_port":"50211","time_iso8601":"2025-07-16T10:04:03+00:00","ssl_client_s_dn":"/C=CA/CN=cdn.ca","request":"GET /asset.js HTTP/1.1","status":200,"request_time":0.087,"request_length":340,"bytes_sent":512,"body_bytes_sent":512,"http_referer":"https://example.ca","http_user_agent":"Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X)","server_name":"cdn.ca.net","server_port":"443","uri":"/asset.js"}
{"remote_addr":"2606:4700:4700::1111","remote_port":"55443","time_iso8601":"2025-07-16T10:04:41+00:00","ssl_client_s_dn":"","request":"GET /dns-query HTTP/2","status":200,"request_time":0.074,"request_length":128,"bytes_sent":280,"body_bytes_sent":280,"http_referer":"-","http_user_agent":"DoH Client/1.3","server_name":"cloudflare-dns.com","server_port":"443","uri":"/dns-query"}
```

So we now execute with debug and test mode, so we don't post the file to the configured stroom proxy (as we want to see the effect
of resolving ip addresses)


```
# ./stroom_log_collector.py --config stroom_log_collector_nginx.yml --state-dir nstate --queue-dir nqueue --debug --test
2025-08-30T13:15:54.773+1000 INFO Log Collector started with config: stroom_log_collector_nginx.yml, state_dir: nstate, queue_dir: nqueue
2025-08-30T13:15:54.788+1000 INFO Post summary for feed 'NginxAccess-BlackBox-V1.0-EVENTS': 0 succeeded, 0 failed.
2025-08-30T13:15:54.788+1000 INFO Processing log files in order: /var/log/nginx/blackbox_ssl_user.log
2025-08-30T13:15:54.789+1000 DEBUG Processing /var/log/nginx/blackbox_ssl_user.log
2025-08-30T13:15:55.531+1000 DEBUG socket.gethostbyaddr('192.0.2.43') failed: [Errno 1] Unknown host
2025-08-30T13:15:55.536+1000 DEBUG socket.gethostbyaddr('198.51.100.17') failed: [Errno 1] Unknown host
2025-08-30T13:15:55.540+1000 DEBUG socket.gethostbyaddr('172.16.0.24') failed: [Errno 1] Unknown host
2025-08-30T13:15:55.819+1000 DEBUG socket.gethostbyaddr('10.0.0.5') failed: [Errno 1] Unknown host
2025-08-30T13:15:55.823+1000 DEBUG socket.gethostbyaddr('203.0.113.7') failed: [Errno 1] Unknown host
2025-08-30T13:15:55.829+1000 INFO Queued new file nqueue/NginxAccess-BlackBox-V1.0-EVENTS_20250716_100441+0000.log.gz for feed NginxAccess-BlackBox-V1.0-EVENTS
2025-08-30T13:15:55.829+1000 INFO [TEST MODE] Would post file nqueue/NginxAccess-BlackBox-V1.0-EVENTS_20250716_100441+0000.log.gz to proxies: ['https://v7stroom-proxy.somedomain.org/stroom/datafeed']
2025-08-30T13:15:55.829+1000 INFO [TEST MODE] with headers Environment: Production; LogType: Nginx Access for capabilty XXX; MyIPAddresses: 192.168.1.107,192.168.122.1,fe80:0000:0000:0000:0a00:27ff:fe1a:b7a9; MyHosts: 192.168.1.107,192.168.122.1,fe80::a00:27ff:fe1a:b7a9,swtf.somedomain.org; MyNameServer: 192.168.1.1; Feed: NginxAccess-BlackBox-V1.0-EVENTS; Compression: GZIP; TZ: Australia/Sydney
2025-08-30T13:15:55.830+1000 INFO Successfully posted and removed file: nqueue/NginxAccess-BlackBox-V1.0-EVENTS_20250716_100441+0000.log.gz
2025-08-30T13:15:55.830+1000 INFO Post summary for feed 'NginxAccess-BlackBox-V1.0-EVENTS': 1 succeeded, 0 failed.
2025-08-30T13:15:55.830+1000 INFO Age-out summary: 0 files deleted for age, 0 files deleted for size, 1 files remain.
2025-08-30T13:15:56.510+1000 INFO Log Collector finished
# 
```

And if we look at the queued files, we see some of the ip addresses identifed and, if possible, resolved

```
# gunzip -c nqueue/NginxAccess-BlackBox-V1.0-EVENTS_20250716_100441+0000.log.gz
{"remote_addr": "8.8.8.8 2606:4700:4700::1111", "remote_port": "53125", "time_iso8601": "2025-07-16T10:01:15+00:00", "ssl_client_s_dn": "/C=US/ST=CA/CN=client1.example.com", "request": "GET /index.html HTTP/1.1", "status": 200, "request_time": 0.123, "request_length": 512, "bytes_sent": 1024, "body_bytes_sent": 512, "http_referer": "-", "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "server_name": "example.com", "server_port": "443", "uri": "/index.html", "_resolv_": {"8.8.8.8": "dns.google", "2606:4700:4700::1111": "one.one.one.one"}}
{"remote_addr": "192.0.2.43", "remote_port": "42022", "time_iso8601": "2025-07-16T10:01:45+00:00", "ssl_client_s_dn": "", "request": "POST /api/data HTTP/1.1", "status": 201, "request_time": 0.308, "request_length": 951, "bytes_sent": 2048, "body_bytes_sent": 2041, "http_referer": "https://example.com/form", "http_user_agent": "curl/7.85.0", "server_name": "api.example.net", "server_port": "443", "uri": "/api/data", "_resolv_": {"192.0.2.43": "-"}}
{"remote_addr": "198.51.100.17", "remote_port": "41234", "time_iso8601": "2025-07-16T10:02:07+00:00", "ssl_client_s_dn": "/C=US/CN=unknown", "request": "GET /image.png HTTP/1.1", "status": 304, "request_time": 0.056, "request_length": 211, "bytes_sent": 0, "body_bytes_sent": 0, "http_referer": "https://img.example.com", "http_user_agent": "Mozilla/5.0 (X11; Linux x86_64)", "server_name": "cdn.example.org", "server_port": "443", "uri": "/image.png", "_resolv_": {"198.51.100.17": "-"}}
{"remote_addr": "172.16.0.24", "remote_port": "53782", "time_iso8601": "2025-07-16T10:02:31+00:00", "ssl_client_s_dn": "", "request": "GET /private/dashboard HTTP/1.1", "status": 403, "request_time": 0.201, "request_length": 1435, "bytes_sent": 2500, "body_bytes_sent": 1500, "http_referer": "-", "http_user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "server_name": "dashboard.local", "server_port": "443", "uri": "/private/dashboard", "_resolv_": {"172.16.0.24": "-"}}
{"remote_addr": "45.33.32.156", "remote_port": "61612", "time_iso8601": "2025-07-16T10:03:01+00:00", "ssl_client_s_dn": "/C=DE/L=Berlin/CN=user.de", "request": "GET /shop HTTP/1.1", "status": 200, "request_time": 0.099, "request_length": 650, "bytes_sent": 800, "body_bytes_sent": 800, "http_referer": "https://referer.example", "http_user_agent": "Mozilla/5.0 (Android 12; Mobile)", "server_name": "shop.example.com", "server_port": "443", "uri": "/shop", "_resolv_": {"45.33.32.156": "scanme.nmap.org"}}
{"remote_addr": "10.0.0.5", "remote_port": "61001", "time_iso8601": "2025-07-16T10:03:27+00:00", "ssl_client_s_dn": "", "request": "GET /internal/ping HTTP/1.1", "status": 200, "request_time": 0.005, "request_length": 60, "bytes_sent": 100, "body_bytes_sent": 100, "http_referer": "-", "http_user_agent": "curl/8.1.2", "server_name": "internal.example.local", "server_port": "443", "uri": "/internal/ping", "_resolv_": {"10.0.0.5": "-"}}
{"remote_addr": "203.0.113.7", "remote_port": "50211", "time_iso8601": "2025-07-16T10:04:03+00:00", "ssl_client_s_dn": "/C=CA/CN=cdn.ca", "request": "GET /asset.js HTTP/1.1", "status": 200, "request_time": 0.087, "request_length": 340, "bytes_sent": 512, "body_bytes_sent": 512, "http_referer": "https://example.ca", "http_user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X)", "server_name": "cdn.ca.net", "server_port": "443", "uri": "/asset.js", "_resolv_": {"203.0.113.7": "-"}}
{"remote_addr": "2606:4700:4700::1111", "remote_port": "55443", "time_iso8601": "2025-07-16T10:04:41+00:00", "ssl_client_s_dn": "", "request": "GET /dns-query HTTP/2", "status": 200, "request_time": 0.074, "request_length": 128, "bytes_sent": 280, "body_bytes_sent": 280, "http_referer": "-", "http_user_agent": "DoH Client/1.3", "server_name": "cloudflare-dns.com", "server_port": "443", "uri": "/dns-query", "_resolv_": {"2606:4700:4700::1111": "one.one.one.one"}}
# 
```

## Example 4

In this example, we want to monitor a [Squid](https://squid-cache.org) Proxy where the access log has been configured to use the Squid Plux logging format. This format is configured as per

```
# Logging
# SquidPlus format is
# %ts.%03tu     Seconds since epoch '.' subsecond time (milliseconds)
# %tr           Response time (milliseconds)
# %>a/%>p       Client source IP address '/' Client source port
# %<a/%<p       Server IP address of the last server or peer connection '/' Server port number of the last server or peer connection
# %<la/%<lp     Local IP address of the last server or peer connection '/' Local port number of the last server or peer connection
# %>la/%>lp     Local IP address the client connected to '/' Local port number the client connected to
#
# %Ss/%>Hs/%<Hs Squid request status (TCP_MISS etc) '/' HTTP status code sent to the client '/' HTTP status code received from the next hop
# %<st/%<sh     Total size of reply sent to client (after adaptation) '/' Size of reply headers sent to client (after adaptation)
# %>st/%>sh     Total size of request received from client. '/' Size of request headers received from client
# %mt           MIME content type
# %rm           Request method (GET/POST etc)
# "%ru"         '"' Request URL from client (historic, filtered for logging) '"'
# "%un"         '"' User name (any available) '"'
# %Sh           Squid hierarchy status (DEFAULT_PARENT etc)
# "%>h"         '"' Original received request header. '"'
# "%<h"         '"' Reply header. '"'
#
# Comment out standard access log directive
# access_log stdio:/var/log/squid/access.log squid
logformat squidplus %ts.%03tu %tr %>a/%>p %<a/%<p %<la/%<lp %>la/%>lp %Ss/%>Hs/%<Hs %<st/%<sh %>st/%>sh %mt %rm "%ru" "%un" %Sh "%>h" "%<h"
logfile_rotate 10
access_log stdio:/var/log/squid/access.log squidplus
# Turn off stripping query terms
strip_query_terms off
```

So our configuration file for this might look like

```
# Main list of Stroom proxy endpoints to post logs to (failover order)
stroom_proxies:
  - https://v7stroom-proxy.somedomain.org/stroom/datafeed

# TLS/SSL configuration for HTTPS requests
tls:
  ca_cert: "false"                       # (string "false" disables verification, not recommended for production)

# Default timeout (in seconds) for posting logs to proxies
timeout_seconds: 10

# List of log sources ("feeds") to monitor and post
feeds:
  - name: StroomSquidPlus                               # Unique identifier for this feed (used in state file)
    log_pattern: /var/log/squid/access.log*             # Glob pattern for log files (rotated and base)
    feed_name: Squid-SquidPlus-V1.0-EVENTS              # Stroom feed name to use in HTTP header
    headers:                                # (Optional) Additional HTTP headers for this feed
      Environment: Production
      LogType: Squid Access logs for capabilty XXX
    custom_formats:                      # (Optional) List of custom timestamp regex/format pairs
      - regex: '^(\d+(\.\d+)?)'          # E.G. 1723295764.994 or 1723295764
        format: 'epoch'                  # To indicate an epoch format
    enrich_ip: true                      # (Optional) If true, append FQDNs for all IPs in each line
    json_mode: false                     # (Optional) If true, treat the input line as a json fragment
    queue_time_limit_days: 7             # (Optional) Max age (days) for queued files for this feed
    queue_size_limit_mb: 500             # (Optional) Max queue size (MB) for this feed
    timeout_seconds: 20                  # (Optional) Override global timeout for this feed

# Default retention/queue settings (used if not overridden per-feed)
defaults:
  queue_time_limit_days: 14        # Max age (days) for queued files
  queue_size_limit_mb: 1024        # Max total size (MB) for queued files
```

We will use some sample Squid access logs generated from the internet

```
1723295761.123 210 203.0.113.5/52314 93.184.216.34/80 10.0.0.5/55432 10.0.0.1/3128 TCP_HIT/200/200 512/450 512/450 http GET "http://example.com/index.html" "alice" direct "User-Agent:Mozilla/5.0" "Server:nginx"
1723295761.445 320 192.0.2.47/51122 1.1.1.1/443 10.0.0.8/55440 10.0.0.1/3128 TCP_MISS/200/200 1024/670 1024/670 https GET "https://cloudflare.com/" "bob" direct "User-Agent:curl/7.68.0" "Server:cloudflare"
1723295762.002 150 198.51.100.10/50233 142.250.217.14/443 10.0.0.9/55456 10.0.0.1/3128 TCP_HIT/200/200 2048/800 2048/800 https GET "https://www.google.com/" "charlie" direct "User-Agent:Mozilla/5.0" "Server:gws"
1723295762.521 412 203.0.113.25/49300 8.8.8.8/53 10.0.0.7/55460 10.0.0.1/3128 TCP_MISS/200/200 128/110 128/110 udp QUERY "udp://8.8.8.8:53/domain" "-" direct "Client-Proto:UDP" "Server-Proto:UDP"
1723295763.033 180 203.0.113.112/61122 151.101.1.69/80 10.0.0.6/55490 10.0.0.1/3128 TCP_HIT/200/200 4096/1024 4096/1024 http GET "http://fastly.net/" "dana" direct "User-Agent:Mozilla/5.0" "Server:Varnish"
1723295763.412 95 198.51.100.77/60244 2606:4700:4700::1111/443 10.0.0.4/55500 10.0.0.1/3128 TCP_MISS/200/200 512/450 512/450 https GET "https://cloudflare-dns.com/" "eve" direct "User-Agent:curl/7.74.0" "Server:cloudflare"
1723295763.878 235 198.51.100.45/50055 93.184.216.34/80 10.0.0.8/55540 10.0.0.1/3128 TCP_HIT/200/200 768/512 768/512 http GET "http://example.com/contact" "frank" direct "User-Agent:Mozilla/5.0" "Server:nginx"
1723295764.112 310 192.0.2.68/52312 151.101.129.140/80 10.0.0.3/55542 10.0.0.1/3128 TCP_MISS/200/200 6144/2038 6144/2038 http GET "http://stackoverflow.com/" "george" direct "User-Agent:Mozilla/5.0" "Server:Apache"
1723295764.500 270 203.0.113.90/53321 104.244.42.1/443 10.0.0.4/55580 10.0.0.1/3128 TCP_HIT/200/200 4096/990 4096/990 https GET "https://twitter.com/" "harry" direct "User-Agent:Mozilla/5.0" "Server:tfe"
1723295764.994 410 198.51.100.34/50210 8.8.4.4/53 10.0.0.2/55600 10.0.0.1/3128 TCP_MISS/200/200 128/120 128/120 udp QUERY "udp://8.8.4.4:53/domain" "-" direct "Client-Proto:UDP" "Server-Proto:UDP"
1723295765.245 130 192.0.2.99/60044 216.58.200.46/443 10.0.0.3/55612 10.0.0.1/3128 TCP_HIT/200/200 1024/640 1024/640 https GET "https://youtube.com/" "ian" direct "User-Agent:Mozilla/5.0" "Server:gvs"
1723295765.712 350 203.0.113.12/49332 13.227.3.21/443 10.0.0.7/55640 10.0.0.1/3128 TCP_REFRESH_MISS/200/200 2048/1400 2048/1400 https GET "https://aws.amazon.com/" "jane" direct "User-Agent:Mozilla/5.0" "Server:AmazonS3"
1723295766.001 280 198.51.100.99/50455 157.240.229.35/443 10.0.0.9/55680 10.0.0.1/3128 TCP_MISS/200/200 8192/3600 8192/3600 https GET "https://facebook.com/" "kim" direct "User-Agent:Mozilla/5.0" "Server:proxygen"
1723295766.355 190 192.0.2.15/52033 172.217.25.238/443 10.0.0.2/55710 10.0.0.1/3128 TCP_HIT/200/200 5120/2100 5120/2100 https GET "https://maps.google.com/" "leo" direct "User-Agent:Mozilla/5.0" "Server:gws"
1723295766.700 230 203.0.113.200/53322 104.16.132.229/443 10.0.0.6/55750 10.0.0.1/3128 TCP_HIT/200/200 1536/1024 1536/1024 https GET "https://cdn.cloudflare.net/" "mary" direct "User-Agent:Mozilla/5.0" "Server:cloudflare"
```

So we now execute with debug and test mode, so we don't post the file to the configured stroom proxy (as we want to see the effect
of resolving ip addresses)


```
# ./stroom_log_collector.py --config stroom_log_collector_squid.yml --state-dir sstate --queue-dir squeue --debug --test
2025-08-30T13:31:29.456+1000 INFO Log Collector started with config: stroom_log_collector_squid.yml, state_dir: sstate, queue_dir: squeue
2025-08-30T13:31:29.468+1000 INFO Post summary for feed 'Squid-SquidPlus-V1.0-EVENTS': 0 succeeded, 0 failed.
2025-08-30T13:31:29.469+1000 INFO Processing log files in order: /var/log/squid/access.log
2025-08-30T13:31:29.470+1000 DEBUG Processing /var/log/squid/access.log
2025-08-30T13:31:29.474+1000 DEBUG socket.gethostbyaddr('10.0.0.1') failed: [Errno 1] Unknown host
2025-08-30T13:31:29.475+1000 DEBUG socket.gethostbyaddr('203.0.113.5') failed: [Errno 1] Unknown host
2025-08-30T13:31:29.475+1000 DEBUG socket.gethostbyaddr('10.0.0.5') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.036+1000 DEBUG socket.gethostbyaddr('93.184.216.34') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.042+1000 DEBUG socket.gethostbyaddr('10.0.0.1') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.044+1000 DEBUG socket.gethostbyaddr('192.0.2.47') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.045+1000 DEBUG socket.gethostbyaddr('10.0.0.8') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.191+1000 DEBUG socket.gethostbyaddr('10.0.0.1') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.193+1000 DEBUG socket.gethostbyaddr('10.0.0.9') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.195+1000 DEBUG socket.gethostbyaddr('198.51.100.10') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.386+1000 DEBUG socket.gethostbyaddr('10.0.0.1') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.392+1000 DEBUG socket.gethostbyaddr('203.0.113.25') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.394+1000 DEBUG socket.gethostbyaddr('10.0.0.7') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.399+1000 DEBUG socket.gethostbyaddr('10.0.0.1') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.401+1000 DEBUG socket.gethostbyaddr('10.0.0.6') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.403+1000 DEBUG socket.gethostbyaddr('203.0.113.112') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.440+1000 DEBUG socket.gethostbyaddr('151.101.1.69') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.443+1000 DEBUG socket.gethostbyaddr('10.0.0.1') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.444+1000 DEBUG socket.gethostbyaddr('10.0.0.4') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.446+1000 DEBUG socket.gethostbyaddr('198.51.100.77') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.474+1000 DEBUG socket.gethostbyaddr('10.0.0.1') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.477+1000 DEBUG socket.gethostbyaddr('10.0.0.8') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.479+1000 DEBUG socket.gethostbyaddr('198.51.100.45') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.480+1000 DEBUG socket.gethostbyaddr('93.184.216.34') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.485+1000 DEBUG socket.gethostbyaddr('10.0.0.1') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.485+1000 DEBUG socket.gethostbyaddr('151.101.129.140') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.486+1000 DEBUG socket.gethostbyaddr('10.0.0.3') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.487+1000 DEBUG socket.gethostbyaddr('192.0.2.68') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.498+1000 DEBUG socket.gethostbyaddr('10.0.0.4') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.498+1000 DEBUG socket.gethostbyaddr('10.0.0.1') failed: [Errno 1] Unknown host
2025-08-30T13:31:30.500+1000 DEBUG socket.gethostbyaddr('203.0.113.90') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.741+1000 DEBUG socket.gethostbyaddr('104.244.42.1') failed: [Errno 2] Host name lookup failure
2025-08-30T13:31:31.746+1000 DEBUG socket.gethostbyaddr('10.0.0.1') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.747+1000 DEBUG socket.gethostbyaddr('198.51.100.34') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.748+1000 DEBUG socket.gethostbyaddr('10.0.0.2') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.752+1000 DEBUG socket.gethostbyaddr('10.0.0.1') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.759+1000 DEBUG socket.gethostbyaddr('10.0.0.3') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.760+1000 DEBUG socket.gethostbyaddr('192.0.2.99') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.768+1000 DEBUG socket.gethostbyaddr('10.0.0.1') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.770+1000 DEBUG socket.gethostbyaddr('10.0.0.7') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.771+1000 DEBUG socket.gethostbyaddr('203.0.113.12') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.773+1000 DEBUG socket.gethostbyaddr('10.0.0.1') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.774+1000 DEBUG socket.gethostbyaddr('10.0.0.9') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.776+1000 DEBUG socket.gethostbyaddr('198.51.100.99') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.943+1000 DEBUG socket.gethostbyaddr('10.0.0.1') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.945+1000 DEBUG socket.gethostbyaddr('10.0.0.2') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.948+1000 DEBUG socket.gethostbyaddr('192.0.2.15') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.953+1000 DEBUG socket.gethostbyaddr('10.0.0.6') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.953+1000 DEBUG socket.gethostbyaddr('10.0.0.1') failed: [Errno 1] Unknown host
2025-08-30T13:31:31.956+1000 DEBUG socket.gethostbyaddr('203.0.113.200') failed: [Errno 1] Unknown host
2025-08-30T13:31:32.109+1000 DEBUG socket.gethostbyaddr('104.16.132.229') failed: [Errno 1] Unknown host
2025-08-30T13:31:32.114+1000 INFO Queued new file squeue/Squid-SquidPlus-V1.0-EVENTS_20240810_131606.700000+0000.log.gz for feed Squid-SquidPlus-V1.0-EVENTS
2025-08-30T13:31:32.114+1000 INFO [TEST MODE] Would post file squeue/Squid-SquidPlus-V1.0-EVENTS_20240810_131606.700000+0000.log.gz to proxies: ['https://v7stroom-proxy.somedomain.org/stroom/datafeed']
2025-08-30T13:31:32.115+1000 INFO [TEST MODE] with headers Environment: Production; LogType: Squid logs for capabilty XXX; MyIPAddresses: 192.168.1.107,192.168.122.1,fe80:0000:0000:0000:0a00:27ff:fe1a:b7a9; MyHosts: 192.168.1.107,192.168.122.1,fe80::a00:27ff:fe1a:b7a9,swtf.somedomain.org; MyNameServer: 192.168.1.1; Feed: Squid-SquidPlus-V1.0-EVENTS; Compression: GZIP; TZ: Australia/Sydney
2025-08-30T13:31:32.115+1000 INFO Successfully posted and removed file: squeue/Squid-SquidPlus-V1.0-EVENTS_20240810_131606.700000+0000.log.gz
2025-08-30T13:31:32.115+1000 INFO Post summary for feed 'Squid-SquidPlus-V1.0-EVENTS': 1 succeeded, 0 failed.
2025-08-30T13:31:32.116+1000 INFO Age-out summary: 0 files deleted for age, 0 files deleted for size, 1 files remain.
2025-08-30T13:31:32.116+1000 INFO Log Collector finished.
# 
```

And if we look at the queued files, we see some of the ip addresses identifed and, if possible, resolved

```
# gunzip -c squeue/Squid-SquidPlus-V1.0-EVENTS_20240810_131606.700000+0000.log.gz
1723295761.123 210 203.0.113.5/52314 93.184.216.34/80 10.0.0.5/55432 10.0.0.1/3128 TCP_HIT/200/200 512/450 512/450 http GET "http://example.com/index.html" "alice" direct "User-Agent:Mozilla/5.0" "Server:nginx" _resolv_: 10.0.0.1=- 10.0.0.5=- 203.0.113.5=- 93.184.216.34=-
1723295761.445 320 192.0.2.47/51122 1.1.1.1/443 10.0.0.8/55440 10.0.0.1/3128 TCP_MISS/200/200 1024/670 1024/670 https GET "https://cloudflare.com/" "bob" direct "User-Agent:curl/7.68.0" "Server:cloudflare" _resolv_: 1.1.1.1=one.one.one.one 10.0.0.1=- 10.0.0.8=- 192.0.2.47=-
1723295762.002 150 198.51.100.10/50233 142.250.217.14/443 10.0.0.9/55456 10.0.0.1/3128 TCP_HIT/200/200 2048/800 2048/800 https GET "https://www.google.com/" "charlie" direct "User-Agent:Mozilla/5.0" "Server:gws" _resolv_: 10.0.0.1=- 10.0.0.9=- 142.250.217.14=pnlgaa-as-in-f14.1e100.net 198.51.100.10=-
1723295762.521 412 203.0.113.25/49300 8.8.8.8/53 10.0.0.7/55460 10.0.0.1/3128 TCP_MISS/200/200 128/110 128/110 udp QUERY "udp://8.8.8.8:53/domain" "-" direct "Client-Proto:UDP" "Server-Proto:UDP" _resolv_: 10.0.0.1=- 10.0.0.7=- 203.0.113.25=- 8.8.8.8=dns.google
1723295763.033 180 203.0.113.112/61122 151.101.1.69/80 10.0.0.6/55490 10.0.0.1/3128 TCP_HIT/200/200 4096/1024 4096/1024 http GET "http://fastly.net/" "dana" direct "User-Agent:Mozilla/5.0" "Server:Varnish" _resolv_: 10.0.0.1=- 10.0.0.6=- 151.101.1.69=- 203.0.113.112=-
1723295763.412 95 198.51.100.77/60244 2606:4700:4700::1111/443 10.0.0.4/55500 10.0.0.1/3128 TCP_MISS/200/200 512/450 512/450 https GET "https://cloudflare-dns.com/" "eve" direct "User-Agent:curl/7.74.0" "Server:cloudflare" _resolv_: 10.0.0.1=- 10.0.0.4=- 198.51.100.77=- 2606:4700:4700::1111=one.one.one.one
1723295763.878 235 198.51.100.45/50055 93.184.216.34/80 10.0.0.8/55540 10.0.0.1/3128 TCP_HIT/200/200 768/512 768/512 http GET "http://example.com/contact" "frank" direct "User-Agent:Mozilla/5.0" "Server:nginx" _resolv_: 10.0.0.1=- 10.0.0.8=- 198.51.100.45=- 93.184.216.34=-
1723295764.112 310 192.0.2.68/52312 151.101.129.140/80 10.0.0.3/55542 10.0.0.1/3128 TCP_MISS/200/200 6144/2038 6144/2038 http GET "http://stackoverflow.com/" "george" direct "User-Agent:Mozilla/5.0" "Server:Apache" _resolv_: 10.0.0.1=- 10.0.0.3=- 151.101.129.140=- 192.0.2.68=-
1723295764.500  270 203.0.113.90/53321 104.244.42.1/443 10.0.0.4/55580 10.0.0.1/3128 TCP_HIT/200/200 4096/990 4096/990 https GET "https://twitter.com/" "harry" direct "User-Agent:Mozilla/5.0" "Server:tfe" _resolv_: 10.0.0.1=- 10.0.0.4=- 104.244.42.1=- 203.0.113.90=-
1723295764.994 410 198.51.100.34/50210 8.8.4.4/53 10.0.0.2/55600 10.0.0.1/3128 TCP_MISS/200/200 128/120 128/120 udp QUERY "udp://8.8.4.4:53/domain" "-" direct "Client-Proto:UDP" "Server-Proto:UDP" _resolv_: 10.0.0.1=- 10.0.0.2=- 198.51.100.34=- 8.8.4.4=dns.google
1723295765.245 130 192.0.2.99/60044 216.58.200.46/443 10.0.0.3/55612 10.0.0.1/3128 TCP_HIT/200/200 1024/640 1024/640 https GET "https://youtube.com/" "ian" direct "User-Agent:Mozilla/5.0" "Server:gvs" _resolv_: 10.0.0.1=- 10.0.0.3=- 192.0.2.99=- 216.58.200.46=tsa01s08-in-f46.1e100.net
1723295765.712 350 203.0.113.12/49332 13.227.3.21/443 10.0.0.7/55640 10.0.0.1/3128 TCP_REFRESH_MISS/200/200 2048/1400 2048/1400 https GET "https://aws.amazon.com/" "jane" direct "User-Agent:Mozilla/5.0" "Server:AmazonS3" _resolv_: 10.0.0.1=- 10.0.0.7=- 13.227.3.21=server-13-227-3-21.bah53.r.cloudfront.net 203.0.113.12=-
1723295766.001 280 198.51.100.99/50455 157.240.229.35/443 10.0.0.9/55680 10.0.0.1/3128 TCP_MISS/200/200 8192/3600 8192/3600 https GET "https://facebook.com/" "kim" direct "User-Agent:Mozilla/5.0" "Server:proxygen" _resolv_: 10.0.0.1=- 10.0.0.9=- 157.240.229.35=edge-star-mini-shv-02-iad3.facebook.com 198.51.100.99=-
1723295766.355 190 192.0.2.15/52033 172.217.25.238/443 10.0.0.2/55710 10.0.0.1/3128 TCP_HIT/200/200 5120/2100 5120/2100 https GET "https://maps.google.com/" "leo" direct "User-Agent:Mozilla/5.0" "Server:gws" _resolv_: 10.0.0.1=- 10.0.0.2=- 172.217.25.238=pnkula-ad-in-f14.1e100.net 192.0.2.15=-
1723295766.700 230 203.0.113.200/53322 104.16.132.229/443 10.0.0.6/55750 10.0.0.1/3128 TCP_HIT/200/200 1536/1024 1536/1024 https GET "https://cdn.cloudflare.net/" "mary" direct "User-Agent:Mozilla/5.0" "Server:cloudflare" _resolv_: 10.0.0.1=- 10.0.0.6=- 104.16.132.229=- 203.0.113.200=-
#
```

And if we look at the state file, we see the last timestamp 1723295766.700 recorded as an ISO8601 format timestamp

```
# gunzip -c sstate/Squid-SquidPlus-V1.0-EVENTS.json
{"last_timestamp": "2024-08-10T13:16:06.700000+0000"}#
```

---

## Troubleshooting

- **No Files Posted:**  
  Ensure the queue directory is writable and the proxies are reachable. Check TLS certificate/key paths if using mutual authentication.

- **Duplicate or Missing Events:**  
  Confirm that the timestamp format in the configuration matches your log files. The script tries `custom_formats` first, then standard ISO8601 formats.

- **File Aging Not Working:**  
  Verify the `queue_time_limit_days` and `queue_size_limit_mb` settings in your configuration.

---

## Security Considerations

- Protect your TLS keys and certificates with appropriate file permissions.
- Ensure the queue and state directories are only accessible by trusted users.

---

## Extending the Script

- Add new log sources by adding more entries to the `feeds` list in `config.yaml`.
- Adjust header enrichment or aging policies as needed per feed.

---

## LICENCE

    /*
     * This file is part of stroom-community-stroom-log-collector
     *
     * stroom-community-stroom-log-collector is free software: you can redistribute it and/or modify
     * it under the terms of the GNU General Public License as published by
     * the Free Software Foundation, either version 3 of the License, or
     * (at your option) any later version.
     *
     * This program is distributed in the hope that it will be useful,
     * but WITHOUT ANY WARRANTY; without even the implied warranty of
     * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     * GNU General Public License for more details.
     *
     * You should have received a copy of the GNU General Public License
     * along with this program.  If not, see <http://www.gnu.org/licenses/>.
     */
