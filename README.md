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
- **Option to write debug/info logs to standard output** (`--stdout` flag).
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
| `--log-file`   | Path to execution log file         | `stroom_log_collector.log`  |
| `--debug`      | Enable debug logging               | Off (INFO level)            |
| `--test`       | Generate files but do not post     | Off                         |
| `--stdout`     | Write debug/info logs to stdout    | Off                         |

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
--log-file /var/log/stroom_log_collector.log
--stdout


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
If `enrich_ip: true`, each log line is appended with `_resolv_:{ip}={fqdn} {ip}={fqdn} {ip}={fqdn}` for every detected IP address (IPv4/IPv6).

- **File Aging:**  
Files in the queue are deleted if:
 - They are older than `queue_time_limit_days`
 - The total size of the queue exceeds `queue_size_limit_mb` (oldest files deleted first)
 - Defaults are set in the defaults configuration item

- **Execution Logging:**  
All script activity is logged in ISO8601 localtime format to the specified log file and, if `--stdout` is used, to standard output.

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

*/5 * * * * /usr/bin/python3 /opt/stroom/stroom_log_collector/stroom_log_collector/stroom_log_collector.py --config /opt/stroom/stroom_log_collector/config.yaml --state-dir /opt/stroom/stroom_log_collector/state --queue-dir /opt/stroom/stroom_log_collector/queue --log-file /var/log/stroom_log_collector.log


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

