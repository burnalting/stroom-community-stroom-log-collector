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
1.1.1.1 1.1.1.1/54321 - [2025-07-12T10:15:01+10:00] - "CN=Alice Smith,OU=Users,O=Example Corp,L=Sydney,ST=NSW,C=AU" "GET / HTTP/1.1" 200 0.123 512/1024/1024 "https://cloudflare.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" cloudflare.com/443 "/"
139.130.205.54 139.130.205.54/49201 - [2025-07-12T10:15:05+10:00] - "-" "POST /login HTTP/1.1" 302 0.234 256/512/512 "https://www.infrastructure.gov.au/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" infrastructure.gov.au/443 "?redirect=home"
152.91.14.133 152.91.14.133/40001 - [2025-07-12T10:15:09+10:00] - "CN=Charlie Brown,OU=Users,O=Example Corp,L=Brisbane,ST=QLD,C=AU" "GET /news HTTP/1.1" 200 0.198 1024/2048/2048 "https://www.ato.gov.au/" "Mozilla/5.0 (Linux; Android 11)" ato.gov.au/443 ""
202.124.241.178 202.124.241.178/50123 - [2025-07-12T10:15:12+10:00] - "-" "DELETE /api/item/123 HTTP/1.1" 204 0.178 128/256/256 "https://www.abc.net.au/" "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X)" abc.net.au/443 "?delete=123"
128.250.1.21 128.250.1.21/55000 - [2025-07-12T10:15:15+10:00] - "CN=Evan Wright,OU=Users,O=Example Corp,L=Adelaide,ST=SA,C=AU" "PUT /profile HTTP/1.1" 200 0.201 768/1536/1536 "https://www.unimelb.edu.au/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" unimelb.edu.au/443 "?update=1"
149.171.124.3 149.171.124.3/60123 - [2025-07-12T10:15:18+10:00] - "-" "GET /status HTTP/1.1" 200 0.045 64/128/128 "-" "curl/7.80.0" unsw.edu.au/443 ""
54.230.110.108 54.230.110.108/41001 - [2025-07-12T10:15:21+10:00] - "CN=George Hall,OU=Users,O=Example Corp,L=Darwin,ST=NT,C=AU" "PATCH /api/patch HTTP/1.1" 200 0.134 512/1024/1024 "https://www.sbs.com.au/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" sbs.com.au/443 "?patch=7"
202.7.247.33 202.7.247.33/53000 - [2025-07-12T10:15:24+10:00] - "-" "GET /info HTTP/1.1" 200 0.065 128/256/256 "https://www.aph.gov.au/" "Mozilla/5.0 (iPad; CPU OS 14_2 like Mac OS X)" aph.gov.au/443 ""
203.50.2.71 203.50.2.71/41234 - [2025-07-12T10:15:28+10:00] - "CN=Ian O'Neil,OU=Users,O=Example Corp,L=GoldCoast,ST=QLD,C=AU" "HEAD /api/ping HTTP/1.1" 200 0.011 32/64/64 "-" "curl/7.68.0" telstra.com.au/443 ""
203.24.100.1 203.24.100.1/60002 - [2025-07-12T10:15:32+10:00] - "-" "OPTIONS /api/options HTTP/1.1" 200 0.008 16/32/32 "-" "Mozilla/5.0 (Linux; Android 12)" geelongadvertiser.com.au/443 ""
203.55.21.1 203.55.21.1/49153 - [2025-07-12T10:15:35+10:00] - "CN=Kevin Tran,OU=Users,O=Example Corp,L=Geelong,ST=VIC,C=AU" "GET /help HTTP/1.1" 404 0.052 0/0/0 "https://www.thechronicle.com.au/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" thechronicle.com.au/443 "?help"
202.86.144.66 202.86.144.66/53215 - [2025-07-12T10:15:39+10:00] - "-" "GET /user HTTP/1.1" 200 0.076 256/512/512 "https://www.illawarramercury.com.au/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" illawarramercury.com.au/443 "?user=Linda"
203.2.218.214 203.2.218.214/54322 - [2025-07-12T10:15:42+10:00] - "CN=Matt Lee,OU=Users,O=Example Corp,L=Ballarat,ST=VIC,C=AU" "GET /api/ballarat HTTP/1.1" 200 0.088 300/600/600 "https://www.abc.net.au/" "Mozilla/5.0 (Linux; Android 10)" abc.net.au/443 "?city=ballarat"
203.62.3.1 203.62.3.1/49202 - [2025-07-12T10:15:45+10:00] - "-" "POST /api/login HTTP/1.1" 401 0.210 0/0/0 "https://www.education.act.gov.au/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" education.act.gov.au/443 "?login=fail"
1.0.0.1 1.0.0.1/40002 - [2025-07-12T10:15:48+10:00] - "CN=Olga Ivanova,OU=Users,O=Example Corp,L=Darwin,ST=NT,C=AU" "GET /api/darwin HTTP/1.1" 200 0.099 256/512/512 "https://cloudflare.com/" "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X)" cloudflare.com/443 "?city=darwin"
203.50.2.72 203.50.2.72/50124 - [2025-07-12T10:15:51+10:00] - "-" "GET /api/canberra HTTP/1.1" 200 0.134 512/1024/1024 "https://www.telstra.com.au/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" telstra.com.au/443 "?city=canberra"
203.62.4.1 203.62.4.1/49203 - [2025-07-12T10:15:54+10:00] - "CN=Quinn Taylor,OU=Users,O=Example Corp,L=Sydney,ST=NSW,C=AU" "POST /api/post HTTP/1.1" 201 0.256 1024/2048/2048 "https://www.education.act.gov.au/" "curl/7.68.0" education.act.gov.au/443 "?post=true"
203.62.8.1 203.62.8.1/49154 - [2025-07-12T10:15:58+10:00] - "-" "GET /api/melbourne HTTP/1.1" 200 0.076 256/512/512 "https://www.education.act.gov.au/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" education.act.gov.au/443 "?city=melbourne"
203.62.64.2 203.62.64.2/53216 - [2025-07-12T10:16:01+10:00] - "CN=Sam Wong,OU=Users,O=Example Corp,L=Perth,ST=WA,C=AU" "GET /api/perth HTTP/1.1" 200 0.076 256/512/512 "https://www.education.act.gov.au/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" education.act.gov.au/443 "?city=perth"
203.50.2.73 203.50.2.73/54323 - [2025-07-12T10:16:04+10:00] - "-" "GET /api/hobart HTTP/1.1" 200 0.088 300/600/600 "https://www.telstra.com.au/" "Mozilla/5.0 (Linux; Android 10)" telstra.com.au/443 "?city=hobart"
```

So we now execute with debug and test mode, so we don't post the file to the configured stroom proxy (as we want to see the effect
of resolving ip addresses)


```
# ./stroom_log_collector.py --config stroom_log_collector_nginx.yml --state-dir nstate --queue-dir nqueue --debug --test
2025-07-13T17:06:24.887+1000 INFO Log Collector started with config: nginx_samples.yml, state_dir: ns, queue_dir: nq
2025-07-13T17:06:24.908+1000 INFO Post summary for feed 'NginxAccess-BlackBox-V1.0-EVENTS': 0 succeeded, 0 failed.
2025-07-13T17:06:24.909+1000 INFO Processing log files in order: ./nginx_samples.log
2025-07-13T17:06:24.910+1000 DEBUG Processing ./nginx_samples.log
2025-07-13T17:06:24.934+1000 DEBUG socket.gethostbyaddr('139.130.205.54') failed: [Errno 1] Unknown host
2025-07-13T17:06:24.937+1000 DEBUG socket.gethostbyaddr('152.91.14.133') failed: [Errno 1] Unknown host
2025-07-13T17:06:25.008+1000 DEBUG socket.gethostbyaddr('128.250.1.21') failed: [Errno 1] Unknown host
2025-07-13T17:06:30.014+1000 DEBUG socket.gethostbyaddr('149.171.124.3') failed: [Errno 2] Host name lookup failure
2025-07-13T17:06:40.030+1000 DEBUG socket.gethostbyaddr('202.7.247.33') failed: [Errno 2] Host name lookup failure
2025-07-13T17:06:40.313+1000 DEBUG socket.gethostbyaddr('203.2.218.214') failed: [Errno 1] Unknown hostv7stroom-proxy.somedomain.org
2025-07-13T17:06:40.404+1000 DEBUG socket.gethostbyaddr('203.62.3.1') failed: [Errno 1] Unknown host
2025-07-13T17:06:40.479+1000 DEBUG socket.gethostbyaddr('203.62.4.1') failed: [Errno 1] Unknown host
2025-07-13T17:06:40.481+1000 DEBUG socket.gethostbyaddr('203.62.8.1') failed: [Errno 1] Unknown host
2025-07-13T17:06:40.532+1000 DEBUG socket.gethostbyaddr('203.62.64.2') failed: [Errno 1] Unknown host
2025-07-13T17:06:40.536+1000 INFO Queued new file nq/NginxAccess-BlackBox-V1.0-EVENTS_20250712_101604+1000.log.gz for feed NginxAccess-BlackBox-V1.0-EVENTS
2025-07-13T17:06:40.537+1000 INFO [TEST MODE] Would post file nq/NginxAccess-BlackBox-V1.0-EVENTS_20250712_101604+1000.log.gz to proxies: ['https://v7stroom-proxy.somedomain.org/stroom/datafeed']
2025-07-13T17:06:40.538+1000 INFO Successfully posted and removed file: nq/NginxAccess-BlackBox-V1.0-EVENTS_20250712_101604+1000.log.gz
2025-07-13T17:06:40.538+1000 INFO Post summary for feed 'NginxAccess-BlackBox-V1.0-EVENTS': 1 succeeded, 0 failed.
2025-07-13T17:06:40.539+1000 INFO Age-out summary: 0 files deleted for age, 0 files deleted for size, 1 files remain.
2025-07-13T17:06:40.539+1000 INFO Log Collector finished.
# 
```

And if we look at the queued file, we see some of the ip addresses identifed and, if possible, resolved

```
# gunzip -c nq/NginxAccess-BlackBox-V1.0-EVENTS_20250712_101604+1000.log.gz
1.1.1.1 1.1.1.1/54321 - [2025-07-12T10:15:01+10:00] - "CN=Alice Smith,OU=Users,O=Example Corp,L=Sydney,ST=NSW,C=AU" "GET / HTTP/1.1" 200 0.123 512/1024/1024 "https://cloudflare.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" cloudflare.com/443 "/" _resolv_: 1.1.1.1=one.one.one.one
139.130.205.54 139.130.205.54/49201 - [2025-07-12T10:15:05+10:00] - "-" "POST /login HTTP/1.1" 302 0.234 256/512/512 "https://www.infrastructure.gov.au/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" infrastructure.gov.au/443 "?redirect=home" _resolv_: 139.130.205.54=-
152.91.14.133 152.91.14.133/40001 - [2025-07-12T10:15:09+10:00] - "CN=Charlie Brown,OU=Users,O=Example Corp,L=Brisbane,ST=QLD,C=AU" "GET /news HTTP/1.1" 200 0.198 1024/2048/2048 "https://www.ato.gov.au/" "Mozilla/5.0 (Linux; Android 11)" ato.gov.au/443 "" _resolv_: 152.91.14.133=-
202.124.241.178 202.124.241.178/50123 - [2025-07-12T10:15:12+10:00] - "-" "DELETE /api/item/123 HTTP/1.1" 204 0.178 128/256/256 "https://www.abc.net.au/" "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X)" abc.net.au/443 "?delete=123" _resolv_: 202.124.241.178=redirector.servers.netregistry.net
128.250.1.21 128.250.1.21/55000 - [2025-07-12T10:15:15+10:00] - "CN=Evan Wright,OU=Users,O=Example Corp,L=Adelaide,ST=SA,C=AU" "PUT /profile HTTP/1.1" 200 0.201 768/1536/1536 "https://www.unimelb.edu.au/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" unimelb.edu.au/443 "?update=1" _resolv_: 128.250.1.21=-
149.171.124.3 149.171.124.3/60123 - [2025-07-12T10:15:18+10:00] - "-" "GET /status HTTP/1.1" 200 0.045 64/128/128 "-" "curl/7.80.0" unsw.edu.au/443 "" _resolv_: 149.171.124.3=-
54.230.110.108 54.230.110.108/41001 - [2025-07-12T10:15:21+10:00] - "CN=George Hall,OU=Users,O=Example Corp,L=Darwin,ST=NT,C=AU" "PATCH /api/patch HTTP/1.1" 200 0.134 512/1024/1024 "https://www.sbs.com.au/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" sbs.com.au/443 "?patch=7" _resolv_: 54.230.110.108=server-54-230-110-108.osl50.r.cloudfront.net
202.7.247.33 202.7.247.33/53000 - [2025-07-12T10:15:24+10:00] - "-" "GET /info HTTP/1.1" 200 0.065 128/256/256 "https://www.aph.gov.au/" "Mozilla/5.0 (iPad; CPU OS 14_2 like Mac OS X)" aph.gov.au/443 "" _resolv_: 202.7.247.33=-
203.50.2.71 203.50.2.71/41234 - [2025-07-12T10:15:28+10:00] - "CN=Ian O'Neil,OU=Users,O=Example Corp,L=GoldCoast,ST=QLD,C=AU" "HEAD /api/ping HTTP/1.1" 200 0.011 32/64/64 "-" "curl/7.68.0" telstra.com.au/443 "" _resolv_: 203.50.2.71=lon-resolver.telstra.net
203.24.100.1 203.24.100.1/60002 - [2025-07-12T10:15:32+10:00] - "-" "OPTIONS /api/options HTTP/1.1" 200 0.008 16/32/32 "-" "Mozilla/5.0 (Linux; Android 12)" geelongadvertiser.com.au/443 "" _resolv_: 203.24.100.1=ge0-3-505.core0.per01.eftel.com
203.55.21.1 203.55.21.1/49153 - [2025-07-12T10:15:35+10:00] - "CN=Kevin Tran,OU=Users,O=Example Corp,L=Geelong,ST=VIC,C=AU" "GET /help HTTP/1.1" 404 0.052 0/0/0 "https://www.thechronicle.com.au/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" thechronicle.com.au/443 "?help" _resolv_: 203.55.21.1=mx1.a.outbound.createsend.com
202.86.144.66 202.86.144.66/53215 - [2025-07-12T10:15:39+10:00] - "-" "GET /user HTTP/1.1" 200 0.076 256/512/512 "https://www.illawarramercury.com.au/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" illawarramercury.com.au/443 "?user=Linda" _resolv_: 202.86.144.66=n20286z144l66.static.ctmip.net
203.2.218.214 203.2.218.214/54322 - [2025-07-12T10:15:42+10:00] - "CN=Matt Lee,OU=Users,O=Example Corp,L=Ballarat,ST=VIC,C=AU" "GET /api/ballarat HTTP/1.1" 200 0.088 300/600/600 "https://www.abc.net.au/" "Mozilla/5.0 (Linux; Android 10)" abc.net.au/443 "?city=ballarat" _resolv_: 203.2.218.214=-
203.62.3.1 203.62.3.1/49202 - [2025-07-12T10:15:45+10:00] - "-" "POST /api/login HTTP/1.1" 401 0.210 0/0/0 "https://www.education.act.gov.au/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" education.act.gov.au/443 "?login=fail" _resolv_: 203.62.3.1=-
1.0.0.1 1.0.0.1/40002 - [2025-07-12T10:15:48+10:00] - "CN=Olga Ivanova,OU=Users,O=Example Corp,L=Darwin,ST=NT,C=AU" "GET /api/darwin HTTP/1.1" 200 0.099 256/512/512 "https://cloudflare.com/" "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X)" cloudflare.com/443 "?city=darwin" _resolv_: 1.0.0.1=one.one.one.one
203.50.2.72 203.50.2.72/50124 - [2025-07-12T10:15:51+10:00] - "-" "GET /api/canberra HTTP/1.1" 200 0.134 512/1024/1024 "https://www.telstra.com.au/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" telstra.com.au/443 "?city=canberra" _resolv_: 203.50.2.72=lnip-resolver1.telstra.net
203.62.4.1 203.62.4.1/49203 - [2025-07-12T10:15:54+10:00] - "CN=Quinn Taylor,OU=Users,O=Example Corp,L=Sydney,ST=NSW,C=AU" "POST /api/post HTTP/1.1" 201 0.256 1024/2048/2048 "https://www.education.act.gov.au/" "curl/7.68.0" education.act.gov.au/443 "?post=true" _resolv_: 203.62.4.1=-
203.62.8.1 203.62.8.1/49154 - [2025-07-12T10:15:58+10:00] - "-" "GET /api/melbourne HTTP/1.1" 200 0.076 256/512/512 "https://www.education.act.gov.au/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" education.act.gov.au/443 "?city=melbourne" _resolv_: 203.62.8.1=-
203.62.64.2 203.62.64.2/53216 - [2025-07-12T10:16:01+10:00] - "CN=Sam Wong,OU=Users,O=Example Corp,L=Perth,ST=WA,C=AU" "GET /api/perth HTTP/1.1" 200 0.076 256/512/512 "https://www.education.act.gov.au/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" education.act.gov.au/443 "?city=perth" _resolv_: 203.62.64.2=-
203.50.2.73 203.50.2.73/54323 - [2025-07-12T10:16:04+10:00] - "-" "GET /api/hobart HTTP/1.1" 200 0.088 300/600/600 "https://www.telstra.com.au/" "Mozilla/5.0 (Linux; Android 10)" telstra.com.au/443 "?city=hobart" _resolv_: 203.50.2.73=sdns2.telstra.net
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
