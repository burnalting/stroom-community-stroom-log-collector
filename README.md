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
- **Comprehensive host metadata:** Adds all host IPs, FQDNs, and nameservers to HTTP headers when file posting.
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
    enrich_ip: true                      # (Optional) If true, append FQDNs for all IPs in each line
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
 - Plus any custom headers from the feed config

- **IP/FQDN Enrichment:**  
If `enrich_ip: true`, each log line is appended with `_resolv_: {ip}={fqdn} {ip}={fqdn} {ip}={fqdn}` for every detected IP address (IPv4/IPv6).

- **File Aging:**  
Files in the queue are deleted if:
 - They are older than `queue_time_limit_days`
 - The total size of the queue exceeds `queue_size_limit_mb` (oldest files deleted first)
 - Defaults are set in the defaults configuration item

- **Execution Logging:**  
All script activity is logged in ISO8601 localtime format to standard output.

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

In this example, we want to monitor an [Nginx](https://nginx.org) access log that has been configured to use the Nginx blackboxSSLUser logging format. This format
is configured as per

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
  - name: StroomNginx                                   # Unique identifier for this feed (used in state file)
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

So we now execute with debug and test mode, so we don't post the file to the configured stroom proxy (as we want to see the effect
of resolving ip addresses)


```
# ./stroom_log_collector.py --config stroom_log_collector_nginx.yml --state-dir nstate --queue-dir nqueue --debug --test
2025-07-16T19:35:34.087+1000 INFO Log Collector started with config: nginx_samples.yml, state_dir: ns, queue_dir: nq
2025-07-16T19:35:34.109+1000 INFO Post summary for feed 'NginxAccess-BlackBox-V1.0-EVENTS': 0 succeeded, 0 failed.
2025-07-16T19:35:34.111+1000 INFO Processing log files in order: ./nginx_samples.log
2025-07-16T19:35:34.111+1000 DEBUG Processing ./nginx_samples.log
2025-07-16T19:35:34.344+1000 DEBUG socket.gethostbyaddr('192.0.2.43') failed: [Errno 1] Unknown host
2025-07-16T19:35:34.347+1000 DEBUG socket.gethostbyaddr('198.51.100.17') failed: [Errno 1] Unknown host
2025-07-16T19:35:34.350+1000 DEBUG socket.gethostbyaddr('172.16.0.24') failed: [Errno 1] Unknown host
2025-07-16T19:35:34.673+1000 DEBUG socket.gethostbyaddr('10.0.0.5') failed: [Errno 1] Unknown host
2025-07-16T19:35:34.677+1000 DEBUG socket.gethostbyaddr('203.0.113.7') failed: [Errno 1] Unknown host
2025-07-16T19:35:35.579+1000 DEBUG socket.gethostbyaddr('93.184.216.34') failed: [Errno 1] Unknown host
2025-07-16T19:35:35.584+1000 DEBUG socket.gethostbyaddr('fd00::abcd') failed: [Errno 1] Unknown host
2025-07-16T19:35:35.586+1000 INFO Queued new file nq/NginxAccess-BlackBox-V1.0-EVENTS_20250716_100557+0000.log.gz for feed NginxAccess-BlackBox-V1.0-EVENTS
2025-07-16T19:35:35.587+1000 INFO [TEST MODE] Would post file nq/NginxAccess-BlackBox-V1.0-EVENTS_20250716_100557+0000.log.gz to proxies: ['https://v7stroom-proxy.somedomain.org/stroom/datafeed']
2025-07-16T19:35:35.587+1000 INFO Successfully posted and removed file: nq/NginxAccess-BlackBox-V1.0-EVENTS_20250716_100557+0000.log.gz
2025-07-16T19:35:35.588+1000 INFO Post summary for feed 'NginxAccess-BlackBox-V1.0-EVENTS': 1 succeeded, 0 failed.
2025-07-16T19:35:35.589+1000 INFO Age-out summary: 0 files deleted for age, 0 files deleted for size, 1 files remain.
2025-07-16T19:35:35.589+1000 INFO Log Collector finished.
# 
```

And if we look at the queued file, we see some of the ip addresses identifed and, if possible, resolved

```
# gunzip -c nq/NginxAccess-BlackBox-V1.0-EVENTS_20250716_100557+0000.log.gz
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
[root@swtf Network]# cat nginx_samples.log
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
# 
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
