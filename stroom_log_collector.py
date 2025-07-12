#!/usr/bin/env python3
"""
Log Collector and Stroom Proxy Poster (YAML configuration version)
Reads rotated log files, processes new lines based on last seen timestamp, enriches lines,
queues for posting, and reliably posts to Stroom proxies with failover, TLS (including mutual auth),
IPv4/IPv6/FQDN enrichment, and file aging.

Compatible with RHEL7+ (Python 3.6+ recommended).

Requires `requests` and `pyyaml` libraries and optionally `dnspython` for enhanced nameserver discovery



This file is part of stroom-community-stroom-log-collector
Copyright (C) 2025 BurnAlting
stroom-community-stroom-log-collector is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""

import os
import re
import gzip
import glob
import shutil
import socket
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
from requests.packages.urllib3.exceptions import InsecureRequestWarning


# --- Logging Setup ---

class ISO8601Formatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        t = time.localtime(record.created)
        s = time.strftime('%Y-%m-%dT%H:%M:%S', t)
        ms = int(record.msecs)
        tz = time.strftime('%z', t)
        return f"{s}.{ms:03d}{tz}"

class GzipFileHandler(logging.FileHandler):
    def __init__(self, filename, mode='a', encoding=None, delay=False):
        super().__init__(filename, mode, encoding, delay)
        self.baseFilename = filename

    def _open(self):
        return gzip.open(self.baseFilename, self.mode + 't', encoding=self.encoding, errors='replace')

def setup_logging(log_file, debug=False, stdout=False):
    logger = logging.getLogger()
    logger.handlers = []  # Remove any existing handlers
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    if log_file.endswith('.gz'):
        handler = GzipFileHandler(log_file, mode='a', encoding='utf-8')
    else:
        handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    formatter = ISO8601Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    # Optionally log to stdout
    if stdout:
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(formatter)
        console.setLevel(logging.DEBUG if debug else logging.INFO)
        logger.addHandler(console)

def parse_args():
    parser = argparse.ArgumentParser(description="Log Collector and Stroom Proxy Poster (YAML config)")
    parser.add_argument('--config', default='config.yaml', help='Path to YAML configuration file')
    parser.add_argument('--state-dir', default='state', help='Directory for state files')
    parser.add_argument('--queue-dir', default='queue', help='Directory for queue files')
    parser.add_argument('--log-file', default='stroom_log_collector.log', help='Execution log file')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--stdout', action='store_true', help='Write debug/info messages to standard output')
    parser.add_argument('--test', action='store_true', help='Test mode: do not post, generate data and log actions')
    return parser.parse_args()

# --- YAML Configuration Parsing ---

def load_config(config_path):
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def compile_custom_formats(feed):
    """Compile custom_formats from config into (regex, format) tuples."""
    compiled = []
    for entry in feed.get('custom_formats', []):
        regex = re.compile(entry['regex'])
        fmt = entry['format']
        compiled.append((regex, fmt))
    return compiled

# --- Utility Functions ---

def get_all_host_ips():
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

def get_all_fqdns():
    fqdns = set()
    try:
        hostname = socket.gethostname()
        fqdns.add(socket.getfqdn())
        fqdns.add(hostname)
        try:
            fqdns.update(socket.gethostbyaddr(hostname))
        except Exception:
            pass
        for ip in get_all_host_ips():
            try:
                fqdns.add(socket.gethostbyaddr(ip)[0])
            except Exception:
                pass
    except Exception:
        pass
    return sorted(fqdns)

def get_nameservers():
    nameservers = set()
    try:
        with open('/etc/resolv.conf') as f:
            for line in f:
                if line.startswith('nameserver'):
                    nameservers.add(line.split()[1])
    except Exception:
        pass
    try:
        result = subprocess.run(
            ['nmcli', 'dev', 'show'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=2
        )
        for line in result.stdout.splitlines():
            if 'IP4.DNS' in line or 'IP6.DNS' in line:
                parts = line.strip().split()
                if len(parts) == 2:
                    nameservers.add(parts[1])
    except Exception:
        pass
    try:
        result = subprocess.run(
            ['systemd-resolve', '--status'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=2
        )
        for line in result.stdout.splitlines():
            if 'DNS Servers' in line:
                servers = line.split(':', 1)[1].strip().split()
                for ns in servers:
                    nameservers.add(ns)
    except Exception:
        pass
    try:
        result = subprocess.run(
            ['resolvectl', 'status'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=2
        )
        for line in result.stdout.splitlines():
            if 'DNS Servers' in line:
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

def resolve_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return '-'

def extract_ips(line):
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
    # With fractional seconds and timezone (Z or ±hh[:mm])
    (re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+(?:Z|[+-]\d{2}:?\d{2}))'), "%Y-%m-%dT%H:%M:%S.%f%z"),
    # With fractional seconds, no timezone
    (re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)'), "%Y-%m-%dT%H:%M:%S.%f"),
    # Without fractional seconds, with timezone
    (re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2}))'), "%Y-%m-%dT%H:%M:%S%z"),
    # Without fractional seconds, no timezone
    (re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'), "%Y-%m-%dT%H:%M:%S"),
]

def extract_timestamp(line, custom_formats=None):
    # 1. Try custom formats first (if provided)
    if custom_formats:
        for regex, fmt in custom_formats:
            m = regex.search(line)
            if m:
                ts = m.group(1)
                try:
                    # Remove colon in timezone if necessary for Python <3.7
                    if fmt.endswith('%z') and re.search(r'[+-]\d{2}:\d{2}$', ts):
                        ts = ts[:-3] + ts[-2:]
                    return datetime.datetime.strptime(ts, fmt)
                except Exception as e:
                    # logging.debug("String %s for custom format %s, exception %s", ts, fmt, e)
                    continue
    # 2. Fallback to built-in ISO8601 regexes
    for regex, fmt in ISO8601_REGEXES:
        m = regex.search(line)
        if m:
            ts = m.group(1)
            try:
                # Remove colon in timezone if necessary for Python <3.7
                if fmt.endswith('%z') and re.search(r'[+-]\d{2}:\d{2}$', ts):
                    ts = ts[:-3] + ts[-2:]
                return datetime.datetime.strptime(ts, fmt)
            except Exception:
                    # logging.debug("String %s for ISO8601 format %s, exception %s", ts, fmt, e)
                continue
    return None

def load_state(state_dir, feed_name):
    path = os.path.join(state_dir, f"{feed_name}.json")
    if os.path.exists(path):
        import json
        with open(path) as f:
            return json.load(f)
    return {}

def save_state(state_dir, feed_name, state):
    path = os.path.join(state_dir, f"{feed_name}.json")
    import json
    with open(path, 'w') as f:
        json.dump(state, f)

def get_log_files(pattern):
    files = glob.glob(pattern)
    if not files:
        return []
    base = os.path.basename(pattern.split('*')[0])
    base_path = None
    rotated = []
    for f in files:
        if os.path.basename(f) == base:
            base_path = f
        else:
            rotated.append(f)
    rotated.sort()
    result = rotated
    if base_path:
        result.append(base_path)
    return result

def open_logfile(filename, mode='rt', encoding='utf-8'):
    if filename.endswith('.gz'):
        return gzip.open(filename, mode=mode, encoding=encoding, errors='replace')
    else:
        return open(filename, mode=mode, encoding=encoding, errors='replace')

def get_verify_from_tls_opts(tls_opts):
    ca_cert = tls_opts.get("ca_cert", True)
    if isinstance(ca_cert, str) and ca_cert.strip().lower() == "false":
        warnings.simplefilter('ignore', InsecureRequestWarning)
        return False
    return ca_cert if ca_cert else True

def post_file(file_path, proxies, headers, tls_opts, timeout, test_mode=False):
    if test_mode:
        logging.info("[TEST MODE] Would post file %s to proxies: %s", file_path, proxies)
        return True 

    verify = get_verify_from_tls_opts(tls_opts)
    with open(file_path, 'rb') as f:
        data = f.read()
    for proxy in proxies:
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
            else:
                logging.warning("Failed to post file %s to %s: HTTP %s", file_path, proxy, resp.status_code)
        except Exception as e:
            logging.warning("Exception posting file %s to %s: %s", file_path, proxy, e)
    return False


def age_out_files(queue_dir, time_limit_days, size_limit_mb):
    files = sorted(
        [(os.path.getctime(f), f) for f in glob.glob(os.path.join(queue_dir, '*'))],
        key=lambda x: x[0]
    )
    now = time.time()
    for ctime, f in files:
        if (now - ctime) > (time_limit_days * 86400):
            logging.info("Aging out file (time): %s", f)
            os.remove(f)
    files = sorted(
        [(os.path.getctime(f), f, os.path.getsize(f)) for f in glob.glob(os.path.join(queue_dir, '*'))],
        key=lambda x: x[0]
    )
    total_size = sum(size for _, _, size in files)
    while total_size > (size_limit_mb * 1024 * 1024) and files:
        _, f, size = files.pop(0)
        logging.info("Aging out file (size): %s", f)
        os.remove(f)
        total_size -= size

def process_log_files(feed, state_dir, state, queue_dir, host_headers):
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
        # Optimization: skip files not modified since last timestamp
        if last_ts:
            try:
                mtime = os.path.getmtime(log_file)
                if mtime <= last_ts.timestamp():
                    logging.debug("Skipping %s (mtime %s <= last_ts %s)", log_file, mtime, last_ts.timestamp())
                    continue
            except Exception as e:
                logging.warning("Could not stat %s: %s", log_file, e)
        try:
            with open_logfile(log_file) as f:
                logging.debug("Processing %s", log_file)
                for line in f:
                    line = line.rstrip('\n')
                    ts = extract_timestamp(line, custom_formats=custom_formats)
                    if ts is None:
                        logging.debug("Timestamp not matched in line %s", line)
                        continue
                    if last_ts and ts <= last_ts:
                        continue
                    if enrich_ip:
                        _first = True
                        for ip in extract_ips(line):
                            if _first:
                                line += f" _resolv_:"
                                _first = False
                            fqdn = resolve_ip(ip)
                            line += f" {ip}={fqdn}"
                    new_lines.append(line)
                    if max_ts is None or ts > max_ts:
                        max_ts = ts
        except Exception as e:
            # Note, if you get the error 'No such group', the regex used for timestamp extraction probably does not have a capturing group or
            # the regex is failing
            logging.warning("Failed to process log file %s: %s", log_file, e)

    out_file = None
    if new_lines:
        ts_str = max_ts.isoformat().replace(':', '').replace('-', '').replace('T', '_')
        out_file = os.path.join(queue_dir, f"{feed_name}_{ts_str}.log")
        with open(out_file, 'w') as f:
            f.write('\n'.join(new_lines) + '\n')
        gz_file = out_file + '.gz'
        with open(out_file, 'rb') as f_in, gzip.open(gz_file, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.remove(out_file)
        out_file = gz_file
        state["last_timestamp"] = max_ts.strftime("%Y-%m-%dT%H:%M:%S.%f%z")
        save_state(state_dir, feed_name, state)
        logging.info("Queued new file %s for feed %s", gz_file, feed_name)
    return out_file

def post_queued_files(feed, queue_dir, proxies, headers, tls_opts, timeout, test_mode=False):
    queue_files = sorted(glob.glob(os.path.join(queue_dir, f"{feed['feed_name']}_*.gz")), key=os.path.getctime)
    for f in queue_files:
        if post_file(f, proxies, headers, tls_opts, timeout, test_mode=test_mode):
            if test_mode == False:
                os.remove(f)
        else:
            break

def main():
    args = parse_args()
    setup_logging(args.log_file, debug=args.debug, stdout=args.stdout)
    logging.info("Log Collector started with config: %s, state_dir: %s, queue_dir: %s", args.config, args.state_dir, args.queue_dir)
    os.makedirs(args.state_dir, exist_ok=True)
    os.makedirs(args.queue_dir, exist_ok=True)
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

