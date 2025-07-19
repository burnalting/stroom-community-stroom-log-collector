#!/usr/bin/env python3
"""
stroom_log_collector.py

Log Collector and Stroom Proxy Poster (YAML configuration version)

Reads rotated log files, processes new lines based on last seen timestamp, enriches lines,
queues for posting, and reliably posts to Stroom proxies with failover, TLS (including mutual auth),
IPv4/IPv6/FQDN enrichment, and file aging.

Compatible with RHEL7+ (Python 3.6+ recommended).

Requires:
    - requests
    - pyyaml
    - (optional) dnspython for enhanced nameserver discovery

License: GNU GPL v3 or later

"""

import os
import re
import gzip
import glob
import shutil
import socket
import concurrent.futures
import struct
import fcntl
import time
import datetime
import requests
import ipaddress
import subprocess
import argparse
import logging
import yaml
import sys
import warnings
import typing
from pathlib import Path
import json
import signal
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# --- Logging Setup ---

class ISO8601Formatter(logging.Formatter):
    """
    Logging formatter producing ISO8601 timestamps with milliseconds and timezone.

    Returns timestamps in the format: YYYY-MM-DDTHH:MM:SS.mmm+ZZZZ
    """
    def formatTime(self, record, datefmt=None):
        t = time.localtime(record.created)
        s = time.strftime('%Y-%m-%dT%H:%M:%S', t)
        ms = int(record.msecs)
        tz = time.strftime('%z', t)
        return f"{s}.{ms:03d}{tz}"

def setup_logging(debug: bool = False) -> None:
    """
    Configure logging to emit records only to stdout.

    Args:
        debug (bool): Enable debug-level logging if True.
    """
    logger = logging.getLogger()
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    formatter = ISO8601Formatter('%(asctime)s %(levelname)s %(message)s')
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    console.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.addHandler(console)

# --- Signal Handling ---

def handle_signal(signum, frame):
    """
    Handle SIGINT/SIGTERM for graceful shutdown.
    """
    logging.info("Received signal %s, shutting down gracefully...", signum)
    sys.exit(0)

signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

# --- Argument Parsing ---

def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Log Collector and Stroom Proxy Poster (YAML config)")
    parser.add_argument('--config', default='config.yaml', help='Path to YAML configuration file')
    parser.add_argument('--state-dir', default='state', help='Directory for state files')
    parser.add_argument('--queue-dir', default='queue', help='Directory for queue files')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--test', action='store_true', help='Test mode: do not post, generate data and log actions')
    return parser.parse_args()

# --- Configuration Loading and Validation ---

def load_config(config_path: str) -> dict:
    """
    Load YAML configuration from file and validate.

    Args:
        config_path (str): Path to YAML configuration file.

    Returns:
        dict: Parsed configuration.

    Raises:
        ValueError: If required keys are missing.
    """
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    validate_config(config)
    return config

def validate_config(config: dict) -> None:
    """
    Validate that required configuration keys are present.

    Args:
        config (dict): Configuration dictionary.

    Raises:
        ValueError: If required keys are missing.
    """
    required_keys = ['feeds', 'defaults']
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required config key: {key}")

def compile_custom_formats(feed: dict) -> list:
    """
    Compile custom timestamp regex/format pairs from config.

    Args:
        feed (dict): Feed configuration.

    Returns:
        list: List of (compiled regex, format string) tuples.
    """
    compiled = []
    for entry in feed.get('custom_formats', []):
        regex = re.compile(entry['regex'])
        fmt = entry['format']
        compiled.append((regex, fmt))
    return compiled

# --- Utility Functions ---

def get_all_host_ips() -> list:
    """
    Discover all IPv4 and IPv6 addresses assigned to the host.

    Returns:
        list: Sorted list of IP addresses as strings.

    """
    ips = set()
    try:
        for iface in os.listdir('/sys/class/net/'):
            if iface == "lo":
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ip = fcntl.ioctl(
                    s.fileno(),
                    0x8915,
                    struct.pack('256s', iface[:15].encode('utf-8'))
                )[20:24]
                ips.add(socket.inet_ntoa(ip))
            except Exception:
                pass
            try:
                with open('/proc/net/if_inet6') as f:
                    for line in f:
                        parts = line.strip().split()
                        if parts[-1] == iface:
                            ipv6 = ':'.join([parts[0][i:i+4] for i in range(0,32,4)])
                            ips.add(ipv6)
            except Exception:
                pass
    except Exception:
        pass
    return sorted(ips)

def get_all_fqdns() -> list:
    """
    Discover all FQDNs associated with the host.

    Returns:
        list: Sorted list of FQDNs (will always return at least the hostname).

    Note:
        - May be slow or incomplete if DNS is misconfigured.
    """
    fqdns = set()
    try:
        # Always add the system hostname and FQDN
        hostname = socket.gethostname()
        fqdns.add(hostname)
        try:
            fqdn = socket.getfqdn()
            if fqdn:
                fqdns.add(fqdn)
        except Exception as e:
            logging.warning("socket.getfqdn() failed: %s", e)
        # Try to resolve the hostname to all possible names
        try:
            resolved = socket.gethostbyaddr(hostname)
            for name in resolved:
                if isinstance(name, str):
                    fqdns.add(name)
                elif isinstance(name, (list, tuple)):
                    fqdns.update(name)
        except Exception as e:
            logging.warning("socket.gethostbyaddr(%r) failed: %s", hostname, e)
        # Try to resolve all host IPs to names
        for ip in get_all_host_ips():
            try:
                resolved = socket.gethostbyaddr(ip)
                for name in resolved:
                    if isinstance(name, str):
                        fqdns.add(name)
                    elif isinstance(name, (list, tuple)):
                        fqdns.update(name)
            except Exception as e:
                logging.debug("gethostbyaddr(%r) failed: %s", ip, e)
    except Exception as e:
        logging.error("get_all_fqdns encountered a fatal error: %s", e)
    # Always return at least the hostname
    if not fqdns:
        fqdns.add(socket.gethostname())
    return sorted(fqdns)


def get_nameservers() -> list:
    """
    Discover system DNS nameservers.

    Returns:
        list: Sorted list of nameserver IPs.

    Issues:
        - Relies on parsing system files and running subprocesses. May fail silently. (# ISSUE)
    """
    nameservers = set()
    try:
        with open('/etc/resolv.conf') as f:
            for line in f:
                if line.startswith('nameserver'):
                    nameservers.add(line.split()[1])
    except Exception:
        pass
    for cmd in [
        (['nmcli', 'dev', 'show'], 'IP4.DNS', 'IP6.DNS'),
        (['systemd-resolve', '--status'], 'DNS Servers'),
        (['resolvectl', 'status'], 'DNS Servers')
    ]:
        try:
            result = subprocess.run(
                cmd[0],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=2
            )
            for line in result.stdout.splitlines():
                if any(key in line for key in cmd[1:]):
                    servers = line.split(':', 1)[1].strip().split()
                    for ns in servers:
                        nameservers.add(ns)
        except Exception:
            pass
    try:
        import dns.resolver
        resolver = dns.resolver.get_default_resolver()
        for ns in resolver.nameservers:
            nameservers.add(ns)
    except Exception:
        pass
    return sorted(nameservers)

def resolve_ip(ip: str) -> str:
    """
    Resolve an IP address to its FQDN, robust to DNS misconfiguration and timeouts.

    Args:
        ip (str): IP address.

    Returns:
        str: FQDN or '-' if resolution fails or times out.

    Note:
        - DNS lookups may block or fail silently; this version uses a timeout and logs failures.
    """
    # Try using the standard socket library with a timeout
    try:
        # Set a short timeout for DNS resolution (Python 3.5+)
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2.0)  # 2 seconds
        try:
            return socket.gethostbyaddr(ip)[0]
        finally:
            socket.setdefaulttimeout(orig_timeout)
    except Exception as e:
        logging.debug("socket.gethostbyaddr(%r) failed: %s", ip, e)

    # Optionally, try dnspython for more control if installed
    try:
        import dns.reversename
        import dns.resolver
        rev_name = dns.reversename.from_address(ip)
        # Set a short timeout and use system resolvers
        answer = dns.resolver.resolve(rev_name, "PTR", lifetime=2.0)  # 2 second timeout
        for rdata in answer:
            return str(rdata).rstrip('.')  # Remove trailing dot
    except ImportError:
        pass  # dnspython not installed; skip this fallback
    except Exception as e:
        logging.debug("dnspython PTR lookup for %r failed: %s", ip, e)

    # If all methods fail, return '-'
    return '-'

def extract_ips(line: str) -> list:
    """
    Extract all IPv4 and IPv6 addresses from a string.

    Args:
        line (str): Input string.

    Returns:
        list: Sorted list of IP addresses found.
    """
    found = set()
    ipv4_cands = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', line)
    for cand in ipv4_cands:
        try:
            ipaddress.IPv4Address(cand)
            found.add(cand)
        except Exception:
            continue
    tokens = re.findall(r'([0-9a-fA-F:]{2,39})', line)
    for token in tokens:
        if ':' in token:
            try:
                ipaddress.IPv6Address(token)
                found.add(token)
            except Exception:
                continue
    return sorted(found)

# --- ISO8601 Regexes ---

ISO8601_REGEXES = [
    # With fractional seconds and timezone (Z or ±hh[:mm]) e.g. 2025-07-13T17:17:17.123+1000
    (re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+(?:Z|[+-]\d{2}:?\d{2}))'), "%Y-%m-%dT%H:%M:%S.%f%z"),
    # With fractional seconds, no timezone e.g. 2025-07-13T17:17:17.123
    (re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)'), "%Y-%m-%dT%H:%M:%S.%f"),
    #  Without fractional seconds, with timezone e.g. 2025-07-13T17:17:17+1000
    (re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2}))'), "%Y-%m-%dT%H:%M:%S%z"),
    #  Without fractional seconds, no timezone e.g. 2025-07-13T17:17:17
    (re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'), "%Y-%m-%dT%H:%M:%S"),
]

def extract_timestamp(
    line: str,
    custom_formats: list = None,
    warn_on_fail: bool = True
) -> typing.Optional[datetime.datetime]:
    """
    Extract a timestamp from a log line using custom or built-in regexes and formats.
    If all known formats fail, attempts to use dateparser (if installed) as a fallback.

    Args:
        line (str): Log line.
        custom_formats (list, optional): List of (regex, format) tuples.
        warn_on_fail (bool): Log a warning if no timestamp is found.

    Returns:
        datetime.datetime or None: Parsed timestamp, or None if not found.

    Note:
        - Will log a warning if regexes do not match, to avoid silent data loss.
        - If timestamp format changes, will attempt to parse with dateparser if available.
        - May still return None for truly unparseable lines.
    """
    # Try custom formats first (if provided)
    if custom_formats:
        for regex, fmt in custom_formats:
            m = regex.search(line)
            if m:
                ts = m.group(1)
                try:
                    # Handle timezone colon for Python <3.7
                    if fmt.endswith('%z') and re.search(r'[+-]\d{2}:\d{2}$', ts):
                        ts = ts[:-3] + ts[-2:]
                    return datetime.datetime.strptime(ts, fmt)
                except Exception as e:
                    logging.debug("Custom timestamp parse failed for '%s' with format '%s': %s", ts, fmt, e)

    # Try built-in ISO8601 regexes
    for regex, fmt in ISO8601_REGEXES:
        m = regex.search(line)
        if m:
            ts = m.group(1)
            try:
                if fmt.endswith('%z') and re.search(r'[+-]\d{2}:\d{2}$', ts):
                    ts = ts[:-3] + ts[-2:]
                return datetime.datetime.strptime(ts, fmt)
            except Exception as e:
                logging.debug("ISO8601 timestamp parse failed for '%s' with format '%s': %s", ts, fmt, e)

    # Fallback: try using dateparser if available
    try:
        import dateparser
        dt = dateparser.parse(line)
        if dt:
            logging.debug("dateparser successfully parsed timestamp from line: %s", line)
            return dt
    except ImportError:
        pass  # dateparser not installed; skip this fallback

    # If all parsing failed, optionally log a warning
    if warn_on_fail and line.strip():
        logging.warning("No timestamp found or parsed in line: %r", line)
    return None


def load_state(state_dir: str, feed_name: str) -> dict:
    """
    Load collector state from a JSON file.

    Args:
        state_dir (str): Directory for state files.
        feed_name (str): Feed name.

    Returns:
        dict: State data, or empty dict if not found.

    """
    path = Path(state_dir) / f"{feed_name}.json"
    if path.exists():
        with open(path, 'r') as f:
            return json.load(f)
    return {}

def save_state(state_dir: str, feed_name: str, state: dict) -> None:
    """
    Save collector state to a JSON file, using file locking.

    Args:
        state_dir (str): Directory for state files.
        feed_name (str): Feed name.
        state (dict): State data.
    """
    path = Path(state_dir) / f"{feed_name}.json"
    with open(path, 'w') as f:
        import fcntl
        fcntl.flock(f, fcntl.LOCK_EX)
        json.dump(state, f)
        fcntl.flock(f, fcntl.LOCK_UN)

import re

def get_log_files(pattern: str) -> list:
    """
    Get a list of log files matching a glob pattern, robust to various rotation schemes.

    Args:
        pattern (str): Glob pattern (e.g., /var/log/app.log*).

    Returns:
        list: List of log file paths, sorted from oldest rotated to current.

    Note:
        - Handles both .gz and non-.gz rotated files.
        - Sorts rotated files by sequence or timestamp.
        - Skips unreadable files and logs a warning.
        - Handles a wider variety of logrotate conventions.
    """
    files = glob.glob(pattern)
    if not files:
        logging.warning("No log files found matching pattern: %s", pattern)
        return []

    # Extract base log file name (without rotation suffix)
    base = os.path.basename(pattern.split('*')[0])
    base_files = []
    rotated_files = []

    # Regex to match rotated files: e.g., app.log.1, app.log.2.gz, app.log-20240601.gz
    rot_regex = re.compile(
        re.escape(base) + r'(\.(\d+))?(\.gz)?$|'
        + re.escape(base) + r'(-\d{8,})(\.gz)?$'
    )

    for f in files:
        fname = os.path.basename(f)
        m = rot_regex.match(fname)
        if fname == base:
            base_files.append(f)
        elif m:
            rotated_files.append((f, m))

    # Sort rotated files: first by sequence number, then by date, then fallback to ctime
    def sort_key(item):
        f, m = item
        # Numeric rotation (e.g., .1, .2.gz)
        if m.group(2):
            return (0, int(m.group(2)))
        # Date-based rotation (e.g., -20240601.gz)
        elif m.group(4):
            try:
                return (1, int(m.group(4).lstrip('-')))
            except Exception:
                return (2, os.path.getctime(f))
        else:
            return (2, os.path.getctime(f))

    rotated_files.sort(key=sort_key)

    # Filter out unreadable files
    all_files = [f for f, _ in rotated_files] + base_files
    readable_files = []
    for f in all_files:
        try:
            # Check readability by opening for reading in binary mode
            with open(f, 'rb'):
                pass
            readable_files.append(f)
        except Exception as e:
            logging.warning("Skipping unreadable log file %s: %s", f, e)

    logging.info("Processing log files in order: %s", ', '.join(readable_files))
    return readable_files


def open_logfile(filename: str, mode: str = 'rt', encoding: str = 'utf-8'):
    """
    Open a log file, supporting gzip-compressed files.

    Args:
        filename (str): Path to log file.
        mode (str): File open mode.
        encoding (str): Encoding to use.

    Returns:
        file object: Opened file handle, or None if file cannot be opened.

    Note:
        - Will skip files that are not valid gzip or text, but logs the reason for skipping.
    """
    try:
        if filename.endswith('.gz'):
            try:
                # Try to open as gzip
                return gzip.open(filename, mode=mode, encoding=encoding, errors='replace')
            except (OSError, EOFError) as e:
                logging.warning("Skipped file %s: not a valid gzip file or is truncated/corrupt. Reason: %s", filename, e)
                return None
        else:
            return open(filename, mode=mode, encoding=encoding, errors='replace')
    except Exception as e:
        logging.warning("Skipped file %s: cannot be opened as text file. Reason: %s", filename, e)
        return None

def get_local_timezone_name() -> str:
    """
    Determine the system's IANA timezone name as a string.
    
    Returns:
        str: The IANA timezone name (e.g., 'Australia/Sydney').
    
    Raises:
        ImportError: If neither 'zoneinfo' nor 'tzlocal' are available.
    
    Notes:
        - On Python 3.9+, attempts to use the standard library 'zoneinfo'.
        - If unavailable, tries to use the 'tzlocal' package (install via 'pip install tzlocal').
        - Checks common Unix-specific mechanisms for timezone discovery.
        - Designed for portability on RHEL7 and all newer major Linux distributions.
    """
    # Prefer TZ environment variable if present
    tz_env = os.environ.get('TZ')
    if tz_env:
        return tz_env

    # 1. Try Python 3.9+'s zoneinfo
    try:
        try:
            import zoneinfo
            local_tz = datetime.datetime.now().astimezone().tzinfo
            if hasattr(local_tz, 'key'):
                return local_tz.key
        except ImportError:
            pass  # zoneinfo not available, continue to next
    except Exception as e:
        logging.debug("zoneinfo import or usage failed: %s", e)

    # 2. Try tzlocal if available (works on Python 2.7+ and new)
    try:
        try:
            import tzlocal
            try:
                # tzlocal >= 3.0
                return tzlocal.get_localzone_name()
            except AttributeError:
                # tzlocal < 3.0
                return str(tzlocal.get_localzone())
        except ImportError:
            pass  # tzlocal not available, continue to next
    except Exception as e:
        logging.debug("tzlocal usage failed: %s", e)

    # 3. Try parsing /etc/localtime symlink (common on RHEL7+)
    zoneinfo_dir = "/usr/share/zoneinfo/"
    localtime_path = "/etc/localtime"
    try:
        if os.path.islink(localtime_path):
            real_path = os.path.realpath(localtime_path)
            if real_path.startswith(zoneinfo_dir):
                tzname = real_path[len(zoneinfo_dir):]
                if tzname:
                    return tzname
        elif os.path.exists(localtime_path):
            # If localtime is not a symlink (copied file), do a binary compare with zoneinfo
            try:
                import filecmp
            except ImportError:
                filecmp = None
            if filecmp is not None:
                for root, dirs, files in os.walk(zoneinfo_dir):
                    for fname in files:
                        candidate = os.path.join(root, fname)
                        try:
                            if filecmp.cmp(localtime_path, candidate, shallow=False):
                                tzname = candidate[len(zoneinfo_dir):]
                                if tzname:
                                    return tzname
                        except Exception:
                            continue
    except Exception as e:
        logging.debug("Parsing /etc/localtime failed: %s", e)

    # 4. Fallback: UTC
    return "UTC"


def get_verify_from_tls_opts(tls_opts: dict):
    """
    Determine whether to verify SSL certificates based on TLS options.

    Args:
        tls_opts (dict): TLS options.

    Returns:
        bool or str: True/False or path to CA cert.
    """
    ca_cert = tls_opts.get("ca_cert", True)
    if isinstance(ca_cert, str) and ca_cert.strip().lower() == "false":
        warnings.simplefilter('ignore', InsecureRequestWarning)
        return False
    return ca_cert if ca_cert else True

import random
import time
import requests

def post_file_with_retry(
    file_path: str,
    proxies: list,
    headers: dict,
    tls_opts: dict,
    timeout: int,
    test_mode: bool = False,
    max_retries: int = 5,
    backoff: int = 2,
    max_total_time: int = 60
) -> bool:
    """
    Post a file to one or more Stroom proxies, with improved retry and exponential backoff with jitter.

    Args:
        file_path (str): Path to file to post.
        proxies (list): List of proxy URLs.
        headers (dict): HTTP headers.
        tls_opts (dict): TLS options.
        timeout (int): HTTP timeout in seconds.
        test_mode (bool): If True, do not actually post.
        max_retries (int): Max retry attempts per proxy.
        backoff (int): Exponential backoff base.
        max_total_time (int): Maximum total time to spend retrying (seconds).

    Returns:
        bool: True if posted successfully, False otherwise.
    """
    if test_mode:
        logging.info("[TEST MODE] Would post file %s to proxies: %s", file_path, proxies)
        header_str = "; ".join(f"{k}: {v}" for k, v in headers.items())
        logging.info("[TEST MODE] with headers %s", header_str)
        return True

    verify = get_verify_from_tls_opts(tls_opts)
    with open(file_path, 'rb') as f:
        data = f.read()

    for proxy in proxies:
        attempt = 0
        start_time = time.time()
        while attempt < max_retries and (time.time() - start_time) < max_total_time:
            try:
                kwargs = {
                    "data": data,
                    "headers": headers,
                    "timeout": timeout,
                    "verify": verify
                }
                if tls_opts.get("client_cert") and tls_opts.get("client_key"):
                    kwargs["cert"] = (tls_opts["client_cert"], tls_opts["client_key"])
                resp = requests.post(proxy, **kwargs)
                if resp.status_code == 200:
                    logging.info("Posted file %s to %s", file_path, proxy)
                    return True
                elif 400 <= resp.status_code < 500:
                    # Non-retryable client error
                    logging.error("Non-retryable error posting file %s to %s: HTTP %s", file_path, proxy, resp.status_code)
                    break
                else:
                    # Retryable server error
                    logging.warning("Retryable error posting file %s to %s: HTTP %s", file_path, proxy, resp.status_code)
            except (requests.ConnectionError, requests.Timeout) as e:
                logging.warning("Connection error posting file %s to %s (attempt %d): %s", file_path, proxy, attempt + 1, e)
            except Exception as e:
                logging.error("Unexpected exception posting file %s to %s (attempt %d): %s", file_path, proxy, attempt + 1, e, exc_info=True)
                break  # Don't retry on unknown errors

            # Exponential backoff with jitter
            sleep_time = backoff ** attempt + random.uniform(0, 1)
            logging.info("Retrying in %.2f seconds...", sleep_time)
            time.sleep(sleep_time)
            attempt += 1

    logging.error("Failed to post file %s to all proxies after %d attempts.", file_path, max_retries)
    return False


import fnmatch

def age_out_files(
    queue_dir: str,
    time_limit_days: int,
    size_limit_mb: int,
    pattern: str = "*.gz"
) -> None:
    """
    Remove old or oversized files from the queue directory.

    Args:
        queue_dir (str): Directory containing queued files.
        time_limit_days (int): Max file age in days.
        size_limit_mb (int): Max total queue size in MB.
        pattern (str): Pattern to match log files (default: '*.gz').

    Note:
        - Uses mtime for file age.
        - Handles deletion errors gracefully.
        - Only deletes files matching the given pattern.
        - Logs a summary of deletions.
    """
    qdir = Path(queue_dir)
    now = time.time()
    time_limit_sec = time_limit_days * 86400

    # Only match files that look like log files (default: *.gz)
    files = [f for f in qdir.iterdir() if f.is_file() and fnmatch.fnmatch(f.name, pattern)]

    # Remove files older than the time limit
    deleted_for_age = 0
    for f in files:
        try:
            mtime = f.stat().st_mtime
            if (now - mtime) > time_limit_sec:
                f.unlink()
                logging.info("Aged out file (time): %s", f)
                deleted_for_age += 1
        except Exception as e:
            logging.warning("Failed to remove file %s during age-out: %s", f, e)

    # Recompute files after age-based deletions
    files = [f for f in qdir.iterdir() if f.is_file() and fnmatch.fnmatch(f.name, pattern)]
    files = sorted(files, key=lambda f: f.stat().st_mtime)
    total_size = sum(f.stat().st_size for f in files)
    size_limit_bytes = size_limit_mb * 1024 * 1024

    # Remove oldest files until under size limit
    deleted_for_size = 0
    while total_size > size_limit_bytes and files:
        f = files.pop(0)
        try:
            sz = f.stat().st_size
            f.unlink()
            logging.info("Aged out file (size): %s", f)
            total_size -= sz
            deleted_for_size += 1
        except Exception as e:
            logging.warning("Failed to remove file %s during size-based age-out: %s", f, e)

    logging.info(
        "Age-out summary: %d files deleted for age, %d files deleted for size, %d files remain.",
        deleted_for_age, deleted_for_size, len(files)
    )

def enrich_ips_multithreaded(line: str, max_workers: int = 10) -> str:
    """
    Enrich all IP addresses found in the input line with FQDNs using multithreading.

    Args:
        line (str): The original log line potentially containing IP addresses.
        max_workers (int): Maximum number of concurrent threads to use for DNS lookups.

    Returns:
        str: The enriched log line with all resolved IP addresses appended in the format:
             <original_line> _resolv_: IP1=FQDN1 IP2=FQDN2 ...

    Notes:
        - IP addresses are extracted via `extract_ips(line)`.
        - Failed resolutions are replaced with '-' to indicate unknown.
    """
    ips = extract_ips(line)
    if not ips:
        return line

    resolved_map = {}

    # Thread pool for parallel lookups
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(resolve_ip, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                fqdn = future.result(timeout=3.0)  # Future timeout safety
            except Exception as e:
                logging.debug("Failed to resolve %s: %s", ip, e)
                fqdn = '-'
            resolved_map[ip] = fqdn

    # Append hostname resolution to the line
    enriched_line = line + " _resolv_:"
    for ip in ips:
        enriched_line += f" {ip}={resolved_map.get(ip, '-')}"
    return enriched_line


def process_log_files(
    feed: dict,
    state_dir: str,
    state: dict,
    queue_dir: str,
    host_headers: dict
) -> typing.Optional[str]:
    """
    Process log files for a feed, extracting new lines and queuing them for posting.

    Args:
        feed (dict): Feed configuration.
        state_dir (str): Directory for state files.
        state (dict): Current state for this feed.
        queue_dir (str): Directory for queue files.
        host_headers (dict): Host metadata headers.

    Returns:
        str or None: Path to newly queued gzipped file, or None if no new lines.

    Note:
        - May skip lines if timestamp parsing fails, but will issue warning
        - Assumes log rotation naming conventions.
    """
    pattern = feed['log_pattern']
    feed_name = feed['feed_name']
    proxies = feed.get('proxy_overrides') or []
    headers = dict(feed.get('headers', {}))
    headers.update(host_headers)
    headers['Feed'] = feed_name
    headers['Compression'] = 'GZIP'

    custom_formats = compile_custom_formats(feed)
    enrich_ip = feed.get('enrich_ip', False)
    last_ts_str = state.get("last_timestamp")
    last_ts = None
    if last_ts_str:
        try:
            last_ts = datetime.datetime.strptime(last_ts_str, "%Y-%m-%dT%H:%M:%S.%f%z")
        except Exception:
            last_ts = None

    log_files = get_log_files(pattern)
    new_lines = []
    max_ts = last_ts

    for log_file in log_files:
        # Skip files not modified since last timestamp
        if last_ts:
            try:
                mtime = os.path.getmtime(log_file)
                if mtime <= last_ts.timestamp():
                    logging.debug("Skipping %s (mtime %s <= last_ts %s)", log_file, mtime, last_ts.timestamp())
                    continue
            except Exception as e:
                logging.warning("Could not stat %s: %s", log_file, e)

        # --- Robust file opening: skip unreadable/corrupt files ---
        fhandle = open_logfile(log_file)
        if fhandle is None:
            logging.warning("Skipping unreadable or corrupt log file: %s", log_file)
            continue
        with fhandle:
            logging.debug("Processing %s", log_file)
            for line_number, line in enumerate(fhandle, 1):
                try:
                    line = line.rstrip('\n')
                    ts = extract_timestamp(line, custom_formats=custom_formats)
                    if ts is None:
                        logging.warning(
                            "Skipped line %d in %s: could not parse timestamp. Line: %r",
                            line_number, log_file, line[:200]  # Truncate long lines
                        )
                        continue
                    if last_ts and ts <= last_ts:
                        continue
                    if enrich_ip:
                        # Enrich line using multithreaded DNS lookup
                        line = enrich_ips_multithreaded(line)
                    new_lines.append(line)
                    if max_ts is None or ts > max_ts:
                        max_ts = ts
                except Exception as e:
                    # Catch and log any line-level errors, but keep processing
                    logging.error("Error processing line in %s: %s", log_file, e, exc_info=True)
                    continue

    out_file = None
    if new_lines:
        ts_str = max_ts.isoformat().replace(':', '').replace('-', '').replace('T', '_')
        out_file = Path(queue_dir) / f"{feed_name}_{ts_str}.log"
        with open(out_file, 'w') as f:
            f.write('\n'.join(new_lines) + '\n')
        gz_file = str(out_file) + '.gz'
        with open(out_file, 'rb') as f_in, gzip.open(gz_file, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
        out_file.unlink()
        out_file = gz_file
        state["last_timestamp"] = max_ts.strftime("%Y-%m-%dT%H:%M:%S.%f%z")
        save_state(state_dir, feed_name, state)
        logging.info("Queued new file %s for feed %s", gz_file, feed_name)
    return out_file

def post_queued_files(
    feed: dict,
    queue_dir: str,
    proxies: list,
    headers: dict,
    tls_opts: dict,
    timeout: int,
    test_mode: bool = False
) -> None:
    """
    Post all queued files for a feed.

    Args:
        feed (dict): Feed configuration.
        queue_dir (str): Directory for queue files.
        proxies (list): List of proxy URLs.
        headers (dict): HTTP headers.
        tls_opts (dict): TLS options.
        timeout (int): HTTP timeout in seconds.
        test_mode (bool): If True, do not actually post.

    Note:
        - Logs success/failure for each file.
        - Keeps failed files for future retry.
    """
    queue_files = sorted(Path(queue_dir).glob(f"{feed['feed_name']}_*.gz"), key=lambda f: f.stat().st_ctime)
    posted_count = 0
    failed_files = []

    for f in queue_files:
        try:
            success = post_file_with_retry(str(f), proxies, headers, tls_opts, timeout, test_mode=test_mode)
            if success:
                if not test_mode:
                    f.unlink()
                posted_count += 1
                logging.info("Successfully posted and removed file: %s", f)
            else:
                failed_files.append(str(f))
                logging.warning("Failed to post file: %s (will retry later)", f)
        except Exception as e:
            failed_files.append(str(f))
            logging.error("Exception posting file %s: %s", f, e, exc_info=True)

    # Emit a summary
    if failed_files:
        logging.warning(
            "Post summary for feed '%s': %d succeeded, %d failed. Failed files: %s",
            feed['feed_name'], posted_count, len(failed_files), ', '.join(failed_files)
        )
    else:
        logging.info(
            "Post summary for feed '%s': %d succeeded, 0 failed.",
            feed['feed_name'], posted_count
        )


def main() -> None:
    """
    Main entry point for the log collector.

    """
    args = parse_args()
    setup_logging(debug=args.debug)
    logging.info("Log Collector started with config: %s, state_dir: %s, queue_dir: %s", args.config, args.state_dir, args.queue_dir)
    Path(args.state_dir).mkdir(exist_ok=True)
    Path(args.queue_dir).mkdir(exist_ok=True)
    config = load_config(args.config)
    tls_opts = config.get("tls", {})
    host_headers = {
        "MyIPAddresses": ','.join(get_all_host_ips()),
        "MyHosts": ','.join(get_all_fqdns()),
        "MyNameServer": ','.join(get_nameservers())
    }
    for feed in config['feeds']:
        feed_name = feed['feed_name']
        state = load_state(args.state_dir, feed_name)
        proxies = feed.get('proxy_overrides') or config.get('stroom_proxies', [])
        headers = dict(feed.get('headers', {}))
        headers.update(host_headers)
        headers['Feed'] = feed_name
        headers['Compression'] = 'GZIP'
        headers['TZ'] = get_local_timezone_name()
        timeout = feed.get('timeout_seconds', config.get('timeout_seconds', 10))
        post_queued_files(feed, args.queue_dir, proxies, headers, tls_opts, timeout, test_mode=args.test)
        out_file = process_log_files(feed, args.state_dir, state, args.queue_dir, host_headers)
        if out_file:
            post_queued_files(feed, args.queue_dir, proxies, headers, tls_opts, timeout, test_mode=args.test)
        age_out_files(
            args.queue_dir,
            feed.get('queue_time_limit_days', config['defaults']['queue_time_limit_days']),
            feed.get('queue_size_limit_mb', config['defaults']['queue_size_limit_mb'])
        )
    logging.info("Log Collector finished.")

if __name__ == '__main__':
    main()

