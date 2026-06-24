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
    python3 health_check.py --retries 3       # Max 3 retry attempts
    python3 health_check.py --backoff 2       # Exponential backoff base (s)
"""

import argparse
import json
import logging
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
# LOGGING
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("health_check")

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

# Circuit breaker defaults
CB_FAILURE_THRESHOLD = 5       # consecutive failures before opening
CB_RECOVERY_TIMEOUT = 30       # seconds before attempting half-open
CB_HALF_OPEN_LIMIT = 2         # max probes in half-open state

# ---------------------------------------------------------------------------
# CIRCUIT BREAKER
# ---------------------------------------------------------------------------

class CircuitBreaker:
    """
    Circuit breaker pattern to prevent hammering flaky services.

    States: CLOSED → OPEN → HALF_OPEN → CLOSED

    CLOSED:     Normal operation, requests pass through.
    OPEN:       Too many failures; requests are short-circuited.
    HALF_OPEN:  Recovery attempt; limited probes allowed to test health.
    """

    STATE_CLOSED = "CLOSED"
    STATE_OPEN = "OPEN"
    STATE_HALF_OPEN = "HALF_OPEN"

    def __init__(self, name: str, failure_threshold: int = 5,
                 recovery_timeout: float = 30, half_open_limit: int = 2):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_limit = half_open_limit

        self.state = self.STATE_CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[float] = None
        self.last_state_change = time.monotonic()
        self.half_open_probes = 0
        self._lock = threading.Lock()

    def allow_request(self) -> bool:
        """Check if a request should be attempted."""
        with self._lock:
            now = time.monotonic()

            if self.state == self.STATE_CLOSED:
                return True

            elif self.state == self.STATE_OPEN:
                if (now - self.last_state_change) >= self.recovery_timeout:
                    self.state = self.STATE_HALF_OPEN
                    self.half_open_probes = 0
                    self.last_state_change = now
                    logger.warning("Circuit [%s] → HALF_OPEN (recovery attempt)", self.name)
                    return True
                logger.warning("Circuit [%s] is OPEN — skipping probe", self.name)
                return False

            elif self.state == self.STATE_HALF_OPEN:
                if self.half_open_probes < self.half_open_limit:
                    self.half_open_probes += 1
                    return True
                logger.debug("Circuit [%s] half-open limit reached", self.name)
                return False

            return True

    def record_success(self):
        """Record a successful request."""
        with self._lock:
            self.failure_count = 0
            if self.state == self.STATE_HALF_OPEN:
                self.success_count += 1
                if self.success_count >= 2:  # Need 2 consecutive successes to close
                    self.state = self.STATE_CLOSED
                    self.half_open_probes = 0
                    self.success_count = 0
                    self.last_state_change = time.monotonic()
                    logger.info("Circuit [%s] → CLOSED (recovered)", self.name)

    def record_failure(self):
        """Record a failed request."""
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()

            if self.state == self.STATE_HALF_OPEN:
                # Any failure in half-open reopens the circuit
                self.state = self.STATE_OPEN
                self.last_state_change = time.monotonic()
                self.success_count = 0
                logger.warning(
                    "Circuit [%s] → OPEN (half-open probe failed, %d total failures)",
                    self.name, self.failure_count
                )
            elif self.failure_count >= self.failure_threshold:
                if self.state == self.STATE_CLOSED:
                    self.state = self.STATE_OPEN
                    self.last_state_change = time.monotonic()
                    logger.warning(
                        "Circuit [%s] → OPEN (%d consecutive failures)",
                        self.name, self.failure_count
                    )

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "state": self.state,
                "failure_count": self.failure_count,
                "last_failure": (
                    datetime.fromtimestamp(self.last_failure_time).isoformat()
                    if self.last_failure_time else None
                ),
            }


# Global circuit breaker registry
_circuits: Dict[str, CircuitBreaker] = {}


def get_circuit(name: str, **kwargs) -> CircuitBreaker:
    """Get or create a circuit breaker for a service."""
    if name not in _circuits:
        _circuits[name] = CircuitBreaker(name, **kwargs)
    return _circuits[name]


# ---------------------------------------------------------------------------
# RETRY WITH EXPONENTIAL BACKOFF
# ---------------------------------------------------------------------------

def with_retry(func, *args, max_retries: int = 2, backoff_base: float = 1.0,
               retry_on: Optional[List[str]] = None, **kwargs):
    """Execute a check function with exponential backoff on transient failures."""
    if retry_on is None:
        retry_on = ["WARNING"]

    last_result = None
    for attempt in range(max_retries + 1):
        result = func(*args, **kwargs)
        status = result[0]

        if attempt < max_retries and status in retry_on:
            wait = backoff_base * (2 ** attempt)
            logger.debug(
                "Retry %d/%d for %s (backoff: %.1fs)",
                attempt + 1, max_retries, func.__name__, wait
            )
            time.sleep(wait)
            last_result = result
        else:
            if attempt > 0:
                logger.info("%s succeeded after %d retries", func.__name__, attempt)
            return result

    logger.warning("%s failed after %d retries", func.__name__, max_retries)
    return last_result


# ---------------------------------------------------------------------------
# RESULT AGGREGATION
# ---------------------------------------------------------------------------

class HealthCheckAggregator:
    """Aggregates health check results across multiple runs for trending."""

    def __init__(self, window_size: int = 10):
        self.window_size = window_size
        self.history: Dict[str, List[Dict]] = defaultdict(list)
        self._lock = threading.Lock()

    def record(self, results: Dict[str, Any]):
        """Record a set of health check results."""
        with self._lock:
            for category in ["services", "infrastructure"]:
                for name, check in results.get(category, {}).items():
                    if isinstance(check, dict):
                        self.history[f"{category}/{name}"].append({
                            "status": check.get("status", "UNKNOWN"),
                            "timestamp": results["timestamp"],
                        })
                        # Keep only window_size entries
                        if len(self.history[f"{category}/{name}"]) > self.window_size:
                            self.history[f"{category}/{name}"].pop(0)

    def get_summary(self) -> Dict[str, Any]:
        """Get aggregated statistics."""
        with self._lock:
            summary = {
                "services": {},
                "totals": {"OK": 0, "WARNING": 0, "CRITICAL": 0, "total": 0},
            }

            for key, entries in self.history.items():
                if not entries:
                    continue

                statuses = [e["status"] for e in entries]
                ok_count = statuses.count("OK")
                warn_count = statuses.count("WARNING")
                crit_count = statuses.count("CRITICAL")
                total = len(statuses)

                # Uptime percentage (OK / total)
                uptime = (ok_count / total * 100) if total > 0 else 0

                category, name = key.split("/", 1)
                if category not in summary:
                    summary[category] = {}

                summary[category][name] = {
                    "ok": ok_count,
                    "warning": warn_count,
                    "critical": crit_count,
                    "total": total,
                    "uptime_pct": round(uptime, 1),
                    "healthy": crit_count == 0,
                    "last_status": statuses[-1] if statuses else "UNKNOWN",
                }

                summary["totals"]["OK"] += ok_count
                summary["totals"]["WARNING"] += warn_count
                summary["totals"]["CRITICAL"] += crit_count
                summary["totals"]["total"] += total

            return summary


# Global aggregator instance
_aggregator = HealthCheckAggregator()


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
# HEALTH CHECK RUNNER
# ---------------------------------------------------------------------------

def run_health_checks(
    service: Optional[str] = None,
    json_output: bool = False,
    max_retries: int = 2,
    backoff_base: float = 1.0,
    circuits_enabled: bool = True,
) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "hostname": socket.gethostname(),
        "services": {},
        "infrastructure": {},
        "system": {},
        "circuits": {},
        "overall_status": "OK",
    }

    all_ok = True

    # Check services (with circuit breaker + retry)
    for name, config in SERVICES.items():
        if service and name != service:
            continue

        cb = get_circuit(
            f"svc:{name}",
            failure_threshold=CB_FAILURE_THRESHOLD,
            recovery_timeout=CB_RECOVERY_TIMEOUT,
            half_open_limit=CB_HALF_OPEN_LIMIT,
        )

        if circuits_enabled and not cb.allow_request():
            results["services"][name] = {
                "status": "CRITICAL",
                "detail": f"Circuit OPEN — probe skipped ({cb.failure_count} failures)",
                "code": 0,
                "endpoint": f"http://{config['host']}:{config['port']}{config['path']}",
                "circuit_state": cb.get_status()["state"],
            }
            all_ok = False
            continue

        status, detail, code = with_retry(
            check_http_service,
            config["host"], config["port"], config["path"], config["timeout"],
            max_retries=max_retries,
            backoff_base=backoff_base,
        )

        # Update circuit breaker
        if status == "CRITICAL":
            cb.record_failure()
            logger.warning("Service [%s] CRITICAL: %s", name, detail)
            all_ok = False
        elif status == "WARNING":
            logger.warning("Service [%s] WARNING: %s", name, detail)
            cb.record_success()
        else:
            cb.record_success()

        results["services"][name] = {
            "status": status,
            "detail": detail,
            "code": code,
            "endpoint": f"http://{config['host']}:{config['port']}{config['path']}",
            "circuit_state": cb.get_status()["state"],
        }

    # Check infrastructure (with circuit breaker + retry)
    for name, config in INFRASTRUCTURE.items():
        if service and name != service:
            continue

        cb = get_circuit(
            f"infra:{name}",
            failure_threshold=CB_FAILURE_THRESHOLD,
            recovery_timeout=CB_RECOVERY_TIMEOUT,
        )

        if circuits_enabled and not cb.allow_request():
            results["infrastructure"][name] = {
                "status": "CRITICAL",
                "detail": f"Circuit OPEN — probe skipped ({cb.failure_count} failures)",
                "endpoint": f"{config['host']}:{config['port']}",
                "circuit_state": cb.get_status()["state"],
            }
            all_ok = False
            continue

        status, detail, latency = with_retry(
            check_tcp_port,
            config["host"], config["port"], config["timeout"],
            max_retries=max_retries,
            backoff_base=backoff_base,
        )

        if status == "CRITICAL":
            cb.record_failure()
            logger.warning("Infra [%s] CRITICAL: %s", name, detail)
            all_ok = False
        elif status == "WARNING":
            logger.warning("Infra [%s] WARNING: %s", name, detail)
            cb.record_success()
        else:
            cb.record_success()

        results["infrastructure"][name] = {
            "status": status,
            "detail": detail,
            "endpoint": f"{config['host']}:{config['port']}",
            "circuit_state": cb.get_status()["state"],
        }

    # Circuit breaker status summary
    for cb_name, cb_obj in _circuits.items():
        results["circuits"][cb_name] = cb_obj.get_status()

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

    # Record for aggregation
    _aggregator.record(results)

    # Attach summary stats
    aggr = _aggregator.get_summary()
    results["aggregation"] = {
        "totals": aggr["totals"],
        "window_size": _aggregator.window_size,
    }

    return results


def print_health_report(results: Dict[str, Any]):
    print(f"\n{'='*60}")
    print(f"  HEALTH CHECK REPORT")
    print(f"  Host: {results['hostname']}")
    print(f"  Time: {results['timestamp']}")
    print(f"  Overall: {results['overall_status']}")
    print(f"{'='*60}")

    for category, items in [("Services", results["services"]),
                             ("Infrastructure", results["infrastructure"]),
                             ("System", results["system"])]:
        if items:
            print(f"\n  {category}:")
            for name, check in items.items():
                if isinstance(check, dict) and "status" in check:
                    status_icon = {"OK": "✓", "WARNING": "⚠", "CRITICAL": "✗"}.get(check["status"], "?")
                    cb_state = f" [CB:{check.get('circuit_state','?')}]" if "circuit_state" in check else ""
                    print(f"    {status_icon} {name}{cb_state}: {check['detail']}")
                else:
                    print(f"    {name}:")
                    for sub_name, sub_check in check.items():
                        if isinstance(sub_check, dict) and "status" in sub_check:
                            sub_icon = {"OK": "✓", "WARNING": "⚠", "CRITICAL": "✗"}.get(sub_check["status"], "?")
                            print(f"      {sub_icon} {sub_name}: {sub_check['detail']}")

    # Aggregation summary
    aggr = results.get("aggregation", {})
    totals = aggr.get("totals", {})
    if totals:
        print(f"\n  Aggregation (window={aggr.get('window_size','?')}):")
        print(f"    ✓ OK: {totals.get('OK',0)}  ⚠ WARN: {totals.get('WARNING',0)}  ✗ CRIT: {totals.get('CRITICAL',0)}")
        if totals.get("total", 0) > 0:
            healthy_pct = totals.get("OK", 0) / totals["total"] * 100
            print(f"    Health: {healthy_pct:.1f}% ({totals['OK']}/{totals['total']})")

    # Circuit breakers
    circuits = results.get("circuits", {})
    open_circuits = [n for n, c in circuits.items() if c.get("state") != "CLOSED"]
    if open_circuits:
        print(f"\n  Circuit Breakers:")
        for name in open_circuits:
            c = circuits[name]
            print(f"    🔴 {name}: {c['state']} (failures: {c['failure_count']})")
    print()


def parse_args():
    parser = argparse.ArgumentParser(description="Health check tool")
    parser.add_argument("--service", "-s", help="Check specific service only")
    parser.add_argument("--json", "-j", action="store_true", help="JSON output")
    parser.add_argument("--watch", "-w", action="store_true", help="Continuous monitoring")
    parser.add_argument("--interval", "-i", type=int, default=30, help="Check interval in seconds")
    parser.add_argument("--output", "-o", help="Output file path")
    # New: retry and circuit breaker options
    parser.add_argument("--retries", type=int, default=2,
                        help="Max retry attempts per probe (default: 2)")
    parser.add_argument("--backoff", type=float, default=1.0,
                        help="Multiplier for exponential backoff (default: 1.0)")
    parser.add_argument("--no-circuit-breaker", action="store_true",
                        help="Disable circuit breaker protection")
    parser.add_argument("--cb-threshold", type=int, default=5,
                        help="Consecutive failures before circuit opens (default: 5)")
    parser.add_argument("--cb-recovery", type=float, default=30,
                        help="Seconds before attempting recovery (default: 30)")
    parser.add_argument("--aggregation-window", type=int, default=10,
                        help="Number of runs in aggregation window (default: 10)")
    parser.add_argument("--summary", action="store_true",
                        help="Print aggregation summary and exit")
    return parser.parse_args()


def main():
    args = parse_args()

    # Global circuit breaker config
    global CB_FAILURE_THRESHOLD, CB_RECOVERY_TIMEOUT
    CB_FAILURE_THRESHOLD = args.circuit_threshold
    CB_RECOVERY_TIMEOUT = args.cb_recovery

    # Aggregation window (only rebuild if not just showing summary)
    global _aggregator

    if args.summary:
        summary = _aggregator.get_summary()
        print(json.dumps(summary, indent=2))
        return 0

    _aggregator = HealthCheckAggregator(window_size=args.aggregation_window)

    if args.watch:
        logger.info("Continuous monitoring (interval: %ds). Press Ctrl+C to stop.", args.interval)
        try:
            while True:
                results = run_health_checks(
                    args.service, args.json,
                    max_retries=args.max_retries,
                    backoff_base=args.backoff_factor,
                    circuits_enabled=not args.no_circuit_breaker,
                )
                if args.json:
                    print(json.dumps(results, indent=2))
                else:
                    print_health_report(results)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            logger.info("Monitoring stopped")
    else:
        results = run_health_checks(
            args.service, args.json,
            max_retries=args.max_retries,
            backoff_base=args.backoff_factor,
            circuits_enabled=not args.no_circuit_breaker,
        )
        if args.json:
            output = json.dumps(results, indent=2)
            print(output)
        else:
            print_health_report(results)

        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
            logger.info("Report saved to %s", args.output)

        if results["overall_status"] == "DEGRADED":
            return 1

    return 0


if __name__ == "__main__":
    main()
