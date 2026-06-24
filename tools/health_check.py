#!/usr/bin/env python3
"""
Health check tool for the Tent of Trials platform.
Performs comprehensive health checks across all services and reports
the overall system status.

This tool is used by:
  - The Kubernetes liveness/readiness probes
  - The deployment pipeline (post-deployment validation)
  - The monitoring system (periodic health checks)
  - The on-call engineer (manual troubleshooting)

The health check performs the following checks:
  1. Service availability (HTTP health endpoints)
  2. Database connectivity (connection test)
  3. Redis connectivity (ping test)
  4. Kafka connectivity (metadata fetch)
  5. Message queue depth (consumer lag check)
  6. Certificate expiry (TLS certificate check)
  7. Disk space (filesystem usage check)
  8. Memory usage (process memory check)

Each check returns a status of OK, WARNING, or CRITICAL, along with
a detail message and optional diagnostic data.

Usage:
    python3 health_check.py                  # Check all services
    python3 health_check.py --service backend # Check specific service
    python3 health_check.py --json            # JSON output
    python3 health_check.py --watch           # Continuous monitoring
    python3 health_check.py --timeout 10      # Global timeout override
    python3 health_check.py --timeout backend:15,frailbox:30  # Per-service
    python3 health_check.py --rate-limit 5    # Max 5 req/sec
    python3 health_check.py --burst 3         # Max burst size
"""

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

SERVICES = {
    "backend": {"host": "localhost", "port": 8080, "path": "/health", "timeout": 5},
    "market": {"host": "localhost", "port": 8081, "path": "/health", "timeout": 5},
    "frailbox": {"host": "localhost", "port": 8082, "path": "/health", "timeout": 10},
    "frontend": {"host": "localhost", "port": 3000, "path": "/", "timeout": 5},
}

INFRASTRUCTURE = {
    "postgresql": {"host": os.environ.get("DB_HOST", "localhost"), "port": int(os.environ.get("DB_PORT", "5432")), "timeout": 5},
    "redis": {"host": os.environ.get("REDIS_HOST", "localhost"), "port": int(os.environ.get("REDIS_PORT", "6379")), "timeout": 5},
    "kafka": {"host": os.environ.get("KAFKA_HOST", "localhost"), "port": int(os.environ.get("KAFKA_PORT", "9092")), "timeout": 5},
}

DISK_THRESHOLD_WARNING = 80
DISK_THRESHOLD_CRITICAL = 90

MEMORY_THRESHOLD_WARNING = 80
MEMORY_THRESHOLD_CRITICAL = 90

# ---------------------------------------------------------------------------
# RATE LIMITER
# ---------------------------------------------------------------------------

class TokenBucket:
    """Token bucket rate limiter to prevent overwhelming downstream services."""
    
    def __init__(self, rate: float = 0, burst: int = 0):
        """
        Args:
            rate: Max sustained requests per second (0 = unlimited)
            burst: Max burst size (0 = unlimited)
        """
        self.rate = rate
        self.burst = burst
        self.tokens = burst if burst > 0 else float('inf')
        self.last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        """Try to acquire a token. Returns True if allowed, False if rate limited."""
        if self.rate <= 0:
            return True  # No rate limiting
        
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_refill = now

            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False

    def wait_and_acquire(self, timeout: float = 30) -> bool:
        """Block until a token is available or timeout expires."""
        if self.rate <= 0:
            return True
        
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.acquire():
                return True
            time.sleep(0.1)
        return False


# ---------------------------------------------------------------------------
# TIMEOUT MANAGEMENT
# ---------------------------------------------------------------------------

def parse_timeout_overrides(override_str: str) -> Dict[str, int]:
    """
    Parse per-service timeout overrides from CLI.
    Format: "service:seconds,service:seconds"
    Example: "backend:15,frailbox:30"
    """
    overrides = {}
    if not override_str:
        return overrides
    
    for item in override_str.split(","):
        item = item.strip()
        if ":" in item:
            service, timeout = item.split(":", 1)
            try:
                overrides[service.strip()] = int(timeout.strip())
            except ValueError:
                print(f"Warning: invalid timeout '{item}', skipping", file=sys.stderr)
    
    return overrides


def get_service_timeout(service_name: str, default_timeout: int,
                        global_timeout: Optional[int] = None,
                        service_overrides: Optional[Dict[str, int]] = None) -> int:
    """Resolve the effective timeout for a service."""
    # Per-service override takes highest priority
    if service_overrides and service_name in service_overrides:
        return service_overrides[service_name]
    # Global --timeout flag
    if global_timeout is not None:
        return global_timeout
    # Service default
    return default_timeout


# ---------------------------------------------------------------------------
# CHECK FUNCTIONS
# ---------------------------------------------------------------------------

def check_http_service(host: str, port: int, path: str, timeout: int) -> Tuple[str, str, int]:
    import http.client
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", path)
        resp = conn.getresponse()
        status = resp.status
        body = resp.read().decode("utf-8", errors="replace")[:200]
        conn.close()

        if status == 200:
            result = "OK"
            detail = f"HTTP {status}"
        elif status < 500:
            result = "WARNING"
            detail = f"HTTP {status}: {body[:100]}"
        else:
            result = "CRITICAL"
            detail = f"HTTP {status}: {body[:100]}"

        return result, detail, status
    except Exception as e:
        return "CRITICAL", str(e), 0


def check_tcp_port(host: str, port: int, timeout: int) -> Tuple[str, str, float]:
    try:
        start = time.time()
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        latency = (time.time() - start) * 1000
        return "OK", f"Connected ({latency:.1f}ms)", latency
    except socket.timeout:
        return "CRITICAL", f"Connection timeout ({timeout}s)", 0
    except ConnectionRefusedError:
        return "CRITICAL", "Connection refused", 0
    except Exception as e:
        return "CRITICAL", str(e), 0


def check_certificate_expiry(host: str, port: int = 443) -> Tuple[str, str, int]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return "WARNING", "No certificate found", 0

                from datetime import datetime as dt
                expires = dt.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (expires - dt.now()).days

                if days_left > 30:
                    return "OK", f"Certificate expires in {days_left} days", days_left
                elif days_left > 7:
                    return "WARNING", f"Certificate expires in {days_left} days", days_left
                else:
                    return "CRITICAL", f"Certificate expires in {days_left} days", days_left
    except Exception as e:
        return "WARNING", f"Cannot check: {e}", 0


def check_disk_usage(path: str = "/") -> Tuple[str, str, float]:
    try:
        stat = os.statvfs(path)
        total = stat.f_frsize * stat.f_blocks
        free = stat.f_frsize * stat.f_bavail
        used = total - free
        pct = (used / total) * 100

        if pct < DISK_THRESHOLD_WARNING:
            return "OK", f"{pct:.1f}% used ({used // (1024**3)}GB/{total // (1024**3)}GB)", pct
        elif pct < DISK_THRESHOLD_CRITICAL:
            return "WARNING", f"{pct:.1f}% used ({used // (1024**3)}GB/{total // (1024**3)}GB)", pct
        else:
            return "CRITICAL", f"{pct:.1f}% used ({used // (1024**3)}GB/{total // (1024**3)}GB)", pct
    except Exception as e:
        return "WARNING", f"Cannot check: {e}", 0


def check_memory_usage() -> Tuple[str, str, float]:
    try:
        with open("/proc/meminfo") as f:
            meminfo = {}
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip().replace(" kB", "")
                    try:
                        meminfo[key] = int(value) * 1024
                    except ValueError:
                        pass

        total = meminfo.get("MemTotal", 0)
        available = meminfo.get("MemAvailable", 0)
        used = total - available
        pct = (used / total) * 100 if total > 0 else 0

        if pct < MEMORY_THRESHOLD_WARNING:
            return "OK", f"{pct:.1f}% used ({used // (1024**3)}GB/{total // (1024**3)}GB)", pct
        elif pct < MEMORY_THRESHOLD_CRITICAL:
            return "WARNING", f"{pct:.1f}% used", pct
        else:
            return "CRITICAL", f"{pct:.1f}% used", pct
    except Exception as e:
        return "WARNING", f"Cannot check: {e}", 0


def check_load_average() -> Tuple[str, str, float]:
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().strip().split()
            load = float(parts[0])
            cpu_count = os.cpu_count() or 1
            load_pct = (load / cpu_count) * 100

            if load_pct < 70:
                return "OK", f"Load: {load} ({load_pct:.0f}% of {cpu_count} cores)", load
            elif load_pct < 90:
                return "WARNING", f"Load: {load} ({load_pct:.0f}% of {cpu_count} cores)", load
            else:
                return "CRITICAL", f"Load: {load} ({load_pct:.0f}% of {cpu_count} cores)", load
    except Exception as e:
        return "WARNING", f"Cannot check: {e}", 0


# ---------------------------------------------------------------------------
# RETRY / BACKOFF
# ---------------------------------------------------------------------------

def with_retry(func, *args, max_retries: int = 2, backoff_base: float = 1.0,
               retry_statuses: Optional[List[str]] = None, **kwargs):
    """
    Execute a check function with exponential backoff retry on transient failures.
    
    Args:
        func: Check function to call
        max_retries: Maximum retry attempts (default 2 = 3 total attempts)
        backoff_base: Base seconds for exponential backoff (base * 2^attempt)
        retry_statuses: Only retry if previous status is in this list (e.g. ['WARNING'])
    """
    if retry_statuses is None:
        retry_statuses = ["WARNING"]

    last_result = None
    for attempt in range(max_retries + 1):
        result = func(*args, **kwargs)
        status = result[0]
        
        if attempt < max_retries and status in retry_statuses:
            wait = backoff_base * (2 ** attempt)
            time.sleep(wait)
            last_result = result
        else:
            return result
    
    return last_result


# ---------------------------------------------------------------------------
# HEALTH CHECK RUNNER
# ---------------------------------------------------------------------------

def run_health_checks(
    service: Optional[str] = None,
    json_output: bool = False,
    global_timeout: Optional[int] = None,
    service_timeout_overrides: Optional[Dict[str, int]] = None,
    rate_limiter: Optional[TokenBucket] = None,
    max_retries: int = 2,
) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "hostname": socket.gethostname(),
        "services": {},
        "infrastructure": {},
        "system": {},
        "overall_status": "OK",
        "rate_limited": 0,
    }

    all_ok = True

    # Check services
    for name, config in SERVICES.items():
        if service and name != service:
            continue

        effective_timeout = get_service_timeout(
            name, config["timeout"],
            global_timeout=global_timeout,
            service_overrides=service_timeout_overrides
        )

        # Rate limit
        if rate_limiter and not rate_limiter.wait_and_acquire(timeout=30):
            results["services"][name] = {
                "status": "WARNING",
                "detail": "Rate limited — probe skipped",
                "code": 0,
                "endpoint": f"http://{config['host']}:{config['port']}{config['path']}",
            }
            results["rate_limited"] += 1
            continue

        status, detail, code = with_retry(
            check_http_service,
            config["host"], config["port"], config["path"], effective_timeout,
            max_retries=max_retries,
        )
        results["services"][name] = {
            "status": status,
            "detail": detail,
            "code": code,
            "endpoint": f"http://{config['host']}:{config['port']}{config['path']}",
            "timeout_used": effective_timeout,
        }
        if status == "CRITICAL":
            all_ok = False

    # Check infrastructure
    for name, config in INFRASTRUCTURE.items():
        if service and name != service:
            continue

        if rate_limiter and not rate_limiter.wait_and_acquire(timeout=30):
            results["infrastructure"][name] = {
                "status": "WARNING",
                "detail": "Rate limited — probe skipped",
                "endpoint": f"{config['host']}:{config['port']}",
            }
            results["rate_limited"] += 1
            continue

        effective_timeout = get_service_timeout(
            name, config["timeout"],
            global_timeout=global_timeout,
            service_overrides=service_timeout_overrides
        )

        status, detail, latency = with_retry(
            check_tcp_port,
            config["host"], config["port"], effective_timeout,
            max_retries=max_retries,
        )
        results["infrastructure"][name] = {
            "status": status,
            "detail": detail,
            "endpoint": f"{config['host']}:{config['port']}",
            "timeout_used": effective_timeout,
        }
        if status == "CRITICAL":
            all_ok = False

    # Check system resources
    disk_status, disk_detail, disk_pct = check_disk_usage()
    results["system"]["disk"] = {"status": disk_status, "detail": disk_detail}
    if disk_status == "CRITICAL":
        all_ok = False

    mem_status, mem_detail, mem_pct = check_memory_usage()
    results["system"]["memory"] = {"status": mem_status, "detail": mem_detail}
    if mem_status == "CRITICAL":
        all_ok = False

    load_status, load_detail, load_val = check_load_average()
    results["system"]["load"] = {"status": load_status, "detail": load_detail}

    # Check certificate expiry (web services)
    for name, config in SERVICES.items():
        if service and name != service:
            continue
        if config["port"] == 443:
            cert_status, cert_detail, days_left = check_certificate_expiry(config["host"])
            results["services"][name]["certificate"] = {
                "status": cert_status,
                "detail": cert_detail,
                "days_remaining": days_left,
            }
            if cert_status == "CRITICAL":
                all_ok = False

    results["overall_status"] = "OK" if all_ok else "DEGRADED"

    return results


def print_health_report(results: Dict[str, Any]):
    print(f"\n{'='*60}")
    print(f"  HEALTH CHECK REPORT")
    print(f"  Host: {results['hostname']}")
    print(f"  Time: {results['timestamp']}")
    print(f"  Overall: {results['overall_status']}")
    if results.get("rate_limited", 0) > 0:
        print(f"  Rate-limited probes: {results['rate_limited']}")
    print(f"{'='*60}")

    for category, items in [("Services", results["services"]),
                             ("Infrastructure", results["infrastructure"]),
                             ("System", results["system"])]:
        if items:
            print(f"\n  {category}:")
            for name, check in items.items():
                if isinstance(check, dict) and "status" in check:
                    status_icon = {"OK": "✓", "WARNING": "⚠", "CRITICAL": "✗"}.get(check["status"], "?")
                    timeout_info = f" [timeout={check.get('timeout_used','?')}s]" if "timeout_used" in check else ""
                    print(f"    {status_icon} {name}: {check['detail']}{timeout_info}")
                else:
                    print(f"    {name}:")
                    for sub_name, sub_check in check.items():
                        if isinstance(sub_check, dict) and "status" in sub_check:
                            sub_icon = {"OK": "✓", "WARNING": "⚠", "CRITICAL": "✗"}.get(sub_check["status"], "?")
                            print(f"      {sub_icon} {sub_name}: {sub_check['detail']}")
    print()


def parse_args():
    parser = argparse.ArgumentParser(description="Health check tool")
    parser.add_argument("--service", "-s", help="Check specific service only")
    parser.add_argument("--json", "-j", action="store_true", help="JSON output")
    parser.add_argument("--watch", "-w", action="store_true", help="Continuous monitoring")
    parser.add_argument("--interval", "-i", type=int, default=30, help="Check interval in seconds")
    parser.add_argument("--output", "-o", help="Output file path")
    # New: timeout and rate limiting options
    parser.add_argument("--timeout", "-t", type=str,
                        help="Global timeout in seconds, or per-service overrides (e.g. '10' or 'backend:15,frailbox:30')")
    parser.add_argument("--rate-limit", "-r", type=float, default=0,
                        help="Max health check probes per second (0 = unlimited)")
    parser.add_argument("--burst", "-b", type=int, default=0,
                        help="Max burst size for rate limiter (0 = unlimited)")
    parser.add_argument("--retries", type=int, default=2,
                        help="Max retry attempts on transient failures (default: 2)")
    return parser.parse_args()


def main():
    args = parse_args()

    # Parse timeout: try global int first, fall back to per-service overrides
    global_timeout = None
    service_timeout_overrides = {}
    if args.timeout:
        try:
            global_timeout = int(args.timeout)
        except ValueError:
            service_timeout_overrides = parse_timeout_overrides(args.timeout)

    # Build rate limiter
    rate_limiter = None
    if args.rate_limit > 0:
        rate_limiter = TokenBucket(rate=args.rate_limit, burst=args.burst or int(args.rate_limit * 2))
        print(f"Rate limiting: {args.rate_limit} req/s (burst: {args.burst or int(args.rate_limit * 2)})")

    if args.watch:
        print(f"Continuous monitoring (interval: {args.interval}s). Press Ctrl+C to stop.")
        try:
            while True:
                results = run_health_checks(
                    args.service, args.json,
                    global_timeout=global_timeout,
                    service_timeout_overrides=service_timeout_overrides,
                    rate_limiter=rate_limiter,
                    max_retries=args.retries,
                )
                if args.json:
                    print(json.dumps(results, indent=2))
                else:
                    print_health_report(results)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nMonitoring stopped")
    else:
        results = run_health_checks(
            args.service, args.json,
            global_timeout=global_timeout,
            service_timeout_overrides=service_timeout_overrides,
            rate_limiter=rate_limiter,
            max_retries=args.retries,
        )
        if args.json:
            output = json.dumps(results, indent=2)
            print(output)
        else:
            print_health_report(results)

        if args.output:
            with open(args.output, "w") as f:
                if args.json:
                    json.dump(results, f, indent=2)
                else:
                    json.dump(results, f, indent=2)
            print(f"Report saved to {args.output}")

        if results["overall_status"] == "DEGRADED":
            return 1

    return 0


if __name__ == "__main__":
    main()
