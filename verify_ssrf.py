#!/usr/bin/env python3
"""
SSRF Remediation Verification Script
- Sends payloads to a target endpoint
- Detects anomalies: status code, canary string, internal redirects, response time
- Supports out‑of‑band (OOB) callback detection (local server or external)
- Saves a full JSON report + SHA‑256 hash in evidence/

Updated: allows multiple expected HTTP status codes (list or single integer)
"""

import argparse
import hashlib
import ipaddress
import json
import sys
import time
import threading
import socket
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException


# ----------------------------------------------------------------------
# Out‑of‑band callback server (local, for testing)
# ----------------------------------------------------------------------

class CallbackHandler(BaseHTTPRequestHandler):
    """Logs every request to the server's list."""
    def log_request(self, code='-', size='-'):
        pass

    def do_GET(self):
        self._record_request()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''
        self._record_request(body.decode('utf-8', errors='ignore'))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def _record_request(self, body=''):
        self.server.callback_requests.append({
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
            "client": self.client_address[0],
            "timestamp": time.time()
        })


class CallbackServer:
    """
    Context manager for a local HTTP server that logs incoming requests.
    """
    def __init__(self, host='0.0.0.0', port=0):
        self.host = host
        self.port = port
        self.server = None
        self.thread = None
        self.callback_requests = []

    def __enter__(self):
        self.server = HTTPServer((self.host, self.port), CallbackHandler)
        self.server.callback_requests = self.callback_requests
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.1)  # allow server to start
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def get_callback_url(self, path='/'):
        # In production, replace with a public domain
        return f"http://{self.host}:{self.port}{path}"

    def get_interactions(self, timeout=5):
        time.sleep(timeout)
        return self.callback_requests.copy()


# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------

def is_internal_ip(host: str) -> bool:
    """Return True if host points to an internal IP (RFC 1918, loopback, link‑local, metadata)."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    # Exact metadata IPs (AWS)
    if str(ip) in ("169.254.169.254", "169.254.170.2"):
        return True

    # Private, loopback, link‑local (ip.is_link_local catches 169.254.0.0/16)
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return True

    # IPv4‑mapped IPv6 (e.g., ::ffff:169.254.169.254)
    if ip.version == 6 and ip.ipv4_mapped:
        mapped = ip.ipv4_mapped
        return (str(mapped) in ("169.254.169.254", "169.254.170.2") or
                mapped.is_private or mapped.is_loopback or mapped.is_link_local)

    return False


def check_redirect_for_internal(location: str) -> bool:
    parsed = urlparse(location)
    if parsed.hostname:
        return is_internal_ip(parsed.hostname)
    return False


def utc_timestamp_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_timestamp_file() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


# ----------------------------------------------------------------------
# Core testing logic
# ----------------------------------------------------------------------

def run_tests(config: Dict[str, Any], oob_server: Optional[CallbackServer] = None) -> Dict[str, Any]:
    target = config["target"]
    param = config["parameter"]
    payloads = config["payloads"]
    canary = config["canary_string"]

    # Allow expected_rejection_code to be a single int or a list of ints
    expected = config["expected_rejection_code"]
    if isinstance(expected, int):
        expected_codes = [expected]
    elif isinstance(expected, list):
        expected_codes = expected
    else:
        raise ValueError("expected_rejection_code must be an integer or a list of integers")

    session = requests.Session()
    session.max_redirects = 0  # capture first response
    adapter = requests.adapters.HTTPAdapter(max_retries=0)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    results = []
    failed = 0

    for idx, payload in enumerate(payloads, start=1):
        test_id = f"TC-{idx:02d}"
        anomalies = []
        canary_found = False
        location_internal = False
        final_status: Optional[Union[int, str]] = None
        elapsed: Optional[float] = None

        print(f"Testing {test_id}: {payload}", file=sys.stderr)

        try:
            start = time.time()
            resp = session.post(
                target,
                data={param: payload},
                timeout=10,
                allow_redirects=False
            )
            elapsed = time.time() - start

            final_status = resp.status_code

            # 1. Unexpected status code – now supports multiple expected codes
            if resp.status_code not in expected_codes:
                anomalies.append(f"Unexpected status {resp.status_code} (expected {expected_codes})")

            # 2. Canary string in response body
            if canary in resp.text:
                canary_found = True
                anomalies.append("Canary string in response body")

            # 3. Redirect to internal address
            location = resp.headers.get('Location')
            if location and check_redirect_for_internal(location):
                location_internal = True
                anomalies.append("Redirect to internal address")

            # 4. Excessive response time
            if elapsed > 3.0:
                anomalies.append(f"Response time >3s ({elapsed:.2f}s)")

        except RequestException as e:
            elapsed = time.time() - start if 'start' in locals() else None
            anomalies.append(f"Request failed: {e}")
            final_status = "ERROR"
        except Exception as e:
            elapsed = time.time() - start if 'start' in locals() else None
            anomalies.append(f"Unexpected error: {e}")
            final_status = "ERROR"

        # Determine pass/fail
        if anomalies:
            result = "FAIL"
            failed += 1
            reason = " -- " + "; ".join(anomalies)
        else:
            result = "PASS"
            reason = ""

        status_str = str(final_status) if final_status is not None else "N/A"
        time_str = f"{elapsed:.2f}s" if elapsed is not None else "N/A"
        canary_str = "YES" if canary_found else "NO"

        display_lines = [
            f"[{test_id}] Payload : {payload}",
            f"        Status : {status_str} | Time: {time_str} | Canary Found: {canary_str}",
            f"        Result : {result}{reason}"
        ]

        results.append({
            "test_id": test_id,
            "payload": payload,
            "status": final_status,
            "time_seconds": elapsed,
            "canary_found": canary_found,
            "location_internal": location_internal,
            "anomalies": anomalies,
            "result": result,
            "reason": reason.strip(" --") if reason else "",
            "display_lines": display_lines
        })

        for line in display_lines:
            print(line, file=sys.stderr)
        print(file=sys.stderr)

    # After all payloads, check for OOB interactions
    oob_triggered = False
    if oob_server:
        interactions = oob_server.get_interactions(timeout=5)
        if interactions:
            oob_triggered = True
            # Add a synthetic test case for OOB
            oob_display = [
                "[OOB] Out‑of‑band callback detected",
                f"        Details: {len(interactions)} request(s) received",
                "        Result : FAIL -- Callback received"
            ]
            results.append({
                "test_id": "OOB",
                "payload": "N/A",
                "status": "N/A",
                "time_seconds": None,
                "canary_found": False,
                "location_internal": False,
                "anomalies": [f"Out‑of‑band callback: {interactions}"],
                "result": "FAIL",
                "reason": "Callback received",
                "display_lines": oob_display
            })
            failed += 1
            for line in oob_display:
                print(line, file=sys.stderr)
            print(file=sys.stderr)

    total = len(payloads) + (1 if oob_triggered else 0)
    verdict = "PASSED" if failed == 0 else "FAILED"

    return {
        "timestamp": utc_timestamp_iso(),
        "finding": config.get("finding", "ssrf_cloud_metadata"),
        "target": target,
        "expected_rejection_code": expected_codes,  # store normalized list in report
        "canary_string": canary,
        "test_results": results,
        "summary": {
            "total": total,
            "failed": failed,
            "verdict": verdict
        }
    }


def print_report(report: Dict[str, Any]) -> None:
    """Print the human‑readable report to stderr."""
    print("\n" + "=" * 50, file=sys.stderr)
    print("===== REMEDIATION VERIFICATION REPORT =====", file=sys.stderr)
    print(f"Finding : {report['finding']}", file=sys.stderr)
    print(f"Target  : {report['target']}", file=sys.stderr)
    print(f"Timestamp: {report['timestamp']}", file=sys.stderr)

    for r in report["test_results"]:
        for line in r["display_lines"]:
            print(line, file=sys.stderr)

    verdict = report["summary"]["verdict"]
    failed = report["summary"]["failed"]
    total = report["summary"]["total"]
    print(f"===== VERDICT: REMEDIATION {verdict} =====", file=sys.stderr)
    print(f"Failed Tests: {failed} / {total}", file=sys.stderr)


def save_bonus_report(report: Dict[str, Any]) -> None:
    """Save JSON report and SHA‑256 hash in evidence/ directory."""
    evidence_dir = Path("evidence")
    evidence_dir.mkdir(exist_ok=True)

    safe_ts = utc_timestamp_file()
    json_path = evidence_dir / f"report_{safe_ts}.json"
    hash_path = evidence_dir / f"report_{safe_ts}.sha256"

    try:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        sha256 = hashlib.sha256()
        with open(json_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
        hash_hex = sha256.hexdigest()

        with open(hash_path, 'w', encoding='utf-8') as f:
            f.write(hash_hex)

        print(f"\n[Bonus] Report saved to {json_path}", file=sys.stderr)
        print(f"[Bonus] SHA‑256 hash saved to {hash_path}", file=sys.stderr)
    except OSError as e:
        print(f"[Bonus] Error writing report files: {e}", file=sys.stderr)


def load_config(input_source: Optional[str] = None) -> Dict[str, Any]:
    """Load JSON from file or stdin."""
    if input_source:
        with open(input_source, 'r', encoding='utf-8') as f:
            return json.load(f)
    return json.load(sys.stdin)


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="SSRF verification with OOB detection")
    parser.add_argument("input_file", nargs="?", help="JSON input file (stdin if omitted)")
    parser.add_argument("--oob", action="store_true", help="Start local OOB callback server")
    args = parser.parse_args()

    try:
        config = load_config(args.input_file)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON - {e}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f"Error: File '{args.input_file}' not found.", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        return 1

    oob_server = None
    if args.oob:
        try:
            # Find a suitable local IP (not 127.0.0.1) if possible, otherwise fallback
            host = socket.gethostbyname(socket.gethostname())
            if host.startswith("127."):
                host = '0.0.0.0'  # bind to all interfaces
            oob_server = CallbackServer(host=host, port=0)
            oob_server.__enter__()
            callback_url = oob_server.get_callback_url('/test')
            print(f"[OOB] Callback server started at {callback_url}", file=sys.stderr)
            print("[OOB] Make sure your payloads include this URL (or a placeholder you replace).", file=sys.stderr)
        except Exception as e:
            print(f"Error starting OOB server: {e}", file=sys.stderr)
            return 1

    try:
        report = run_tests(config, oob_server)
        print_report(report)
        save_bonus_report(report)
    except Exception as e:
        print(f"Unexpected error during testing: {e}", file=sys.stderr)
        return 1
    finally:
        if oob_server:
            oob_server.__exit__()

    return 0 if report["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
