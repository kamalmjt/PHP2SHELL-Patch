#!/usr/bin/env python3
"""
audit_php2shell.py
Vulnerability Detection Tool for CVE-2026-109618 & CVE-2026-109619 (PHP2Shell).
Audits CLI, PHP-FPM, and Apache mod_php installations against official security thresholds.

Can be run standalone or invoked by Ansible playbooks.
Author: Kamal Majaiti EL Majaiti
"""

import os
import re
import sys
import glob
import json
import socket
import subprocess
from datetime import datetime, timezone

# Official patched versions
# PHP 8.2: >= 8.2.35
# PHP 8.3: >= 8.3.36
# PHP 8.4: >= 8.4.27
# PHP 8.5: >= 8.5.12
PATCH_TARGETS = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

# Binaries built on or after this date include the backported fix, even on EOL
# branches or below the official version thresholds (e.g. sury builds of 7.x).
PATCH_BUILD_DATE = datetime(2026, 10, 21)
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

def parse_semver(ver_str):
    """Extract (major, minor, patch) from version string."""
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", ver_str)
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3)) if m.group(3) else 0
    return (major, minor, patch)

def evaluate_version(ver_tuple):
    """
    Returns (status, target_version_str, message):
      - 'PATCHED'
      - 'VULNERABLE_EOL'
      - 'VULNERABLE_UNPATCHED'
    """
    if not ver_tuple:
        return ("UNKNOWN", None, "Could not determine semantic version.")

    major, minor, patch = ver_tuple

    # PHP < 8.2 (PHP 5.x, 7.x, 8.0, 8.1) are EOL
    if major < 8 or (major == 8 and minor < 2):
        return (
            "VULNERABLE_EOL",
            None,
            f"PHP {major}.{minor}.{patch} is End-of-Life (EOL). No official upstream binary patch exists."
        )

    branch = (major, minor)
    if branch in PATCH_TARGETS:
        req = PATCH_TARGETS[branch]
        target_str = f"{req[0]}.{req[1]}.{req[2]}"
        if ver_tuple >= req:
            return ("PATCHED", target_str, f"Patched against CVE-2026-109618 and CVE-2026-109619 (>= {target_str}).")
        else:
            return (
                "VULNERABLE_UNPATCHED",
                target_str,
                f"Vulnerable: running {major}.{minor}.{patch}, minimum patched version is {target_str}."
            )

    if major > 8 or (major == 8 and minor > 5):
        return ("PATCHED", None, f"Future PHP version {major}.{minor}.{patch} includes core mitigations.")

    return ("UNKNOWN", None, "Unrecognized PHP version branch.")

def get_build_date(path):
    """Build date from '-v' output ("built: Oct 21 2026 14:29:22"), or None."""
    try:
        res = subprocess.run([path, "-v"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, universal_newlines=True)
        m = re.search(r"built:\s*([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{4})", res.stdout)
        if m and m.group(1) in MONTHS:
            return datetime(int(m.group(3)), MONTHS.index(m.group(1)) + 1, int(m.group(2)))
    except Exception:
        pass
    return None

def apply_build_date(status, target_ver, desc, build_date):
    """Vulnerable-by-version binaries built on/after PATCH_BUILD_DATE carry the backported fix."""
    if status in ("VULNERABLE_EOL", "VULNERABLE_UNPATCHED") and build_date and build_date >= PATCH_BUILD_DATE:
        return (
            "PATCHED",
            target_ver,
            f"Patched via backport: built {build_date:%Y-%m-%d} (>= {PATCH_BUILD_DATE:%Y-%m-%d})."
        )
    return (status, target_ver, desc)

def parse_size_bytes(val):
    if not val or val == "-1":
        return -1
    val = val.strip().upper()
    m = re.match(r"^(\d+)\s*([KMGT]?B?)", val)
    if not m:
        return 0
    num = int(m.group(1))
    unit = m.group(2)
    if "G" in unit:
        return num * 1024 * 1024 * 1024
    if "M" in unit:
        return num * 1024 * 1024
    if "K" in unit:
        return num * 1024
    return num

def inspect_cli_binary(path):
    try:
        cmd = [path, "-r", "echo PHP_VERSION . '|||' . ini_get('session.upload_progress.enabled') . '|||' . ini_get('fatal_error_backtraces') . '|||' . ini_get('memory_limit') . '|||' . ini_get('post_max_size');"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8, universal_newlines=True)
        if res.returncode == 0 and "|||" in res.stdout:
            parts = res.stdout.strip().split("|||")
            ver_str = parts[0]
            prog_val = parts[1] if len(parts) > 1 else ""
            bt_val = parts[2] if len(parts) > 2 else ""
            mem_lim = parts[3] if len(parts) > 3 else ""
            post_max = parts[4] if len(parts) > 4 else ""
            return ver_str, prog_val, bt_val, mem_lim, post_max
    except Exception:
        pass

    try:
        res = subprocess.run([path, "-v"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, universal_newlines=True)
        line = res.stdout.splitlines()[0] if res.stdout.splitlines() else ""
        m = re.search(r"PHP\s+(\d+\.\d+\.\d+)", line)
        if m:
            return m.group(1), "", "", "", ""
    except Exception:
        pass
    return None, "", "", "", ""

def inspect_fpm_binary(path):
    try:
        res = subprocess.run([path, "-i"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12, universal_newlines=True)
        info = res.stdout
        ver_str = None
        prog_val = ""
        bt_val = ""
        mem_lim = ""
        post_max = ""
        for line in info.splitlines():
            if line.startswith("PHP Version =>"):
                ver_str = line.split("=>")[1].strip()
            elif line.startswith("session.upload_progress.enabled =>"):
                prog_val = line.split("=>")[1].strip()
            elif line.startswith("fatal_error_backtraces =>"):
                bt_val = line.split("=>")[1].strip()
            elif line.startswith("memory_limit =>"):
                mem_lim = line.split("=>")[1].strip()
            elif line.startswith("post_max_size =>"):
                post_max = line.split("=>")[1].strip()
        if ver_str:
            return ver_str, prog_val, bt_val, mem_lim, post_max
    except Exception:
        pass

    try:
        res = subprocess.run([path, "-v"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, universal_newlines=True)
        line = res.stdout.splitlines()[0] if res.stdout.splitlines() else ""
        m = re.search(r"PHP\s+(\d+\.\d+\.\d+)", line)
        if m:
            return m.group(1), "", "", "", ""
    except Exception:
        pass
    return None, "", "", "", ""

def inspect_so_module(path):
    try:
        res = subprocess.run(["strings", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, universal_newlines=True)
        out = res.stdout
        m = re.search(r"X-Powered-By:\s*PHP/(\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
        m2 = re.search(r"PHP Version =>\s*(\d+\.\d+\.\d+)", out)
        if m2:
            return m2.group(1)
    except Exception:
        pass
    return None

def find_unique_binaries(patterns):
    paths = []
    seen = set()
    for pat in patterns:
        for f in glob.glob(pat):
            if os.path.isfile(f) and os.access(f, os.X_OK):
                try:
                    real = os.path.realpath(f)
                    if real not in seen:
                        seen.add(real)
                        paths.append(real)
                except Exception:
                    pass
    return paths

def run_audit():
    hostname = socket.gethostname()
    findings = []

    # 1. CLI Binaries
    cli_patterns = [
        "/usr/bin/php*",
        "/usr/local/bin/php*",
        "/opt/plesk/php/*/bin/php",
        "/opt/php-*/bin/php",
        "/etc/alternatives/php",
    ]
    cli_bins = find_unique_binaries(cli_patterns)
    for b in cli_bins:
        ver_str, prog_val, bt_val, mem_lim, post_max = inspect_cli_binary(b)
        if not ver_str:
            continue
        semver = parse_semver(ver_str)
        build_date = get_build_date(b)
        status, target_ver, desc = apply_build_date(*evaluate_version(semver), build_date)
        item = {
            "type": "cli",
            "path": b,
            "version": ver_str,
            "build_date": build_date.strftime("%Y-%m-%d") if build_date else None,
            "semver": list(semver) if semver else None,
            "status": status,
            "target_version": target_ver,
            "details": desc,
            "upload_progress_enabled": prog_val.lower() in ["1", "on", "true"],
            "fatal_error_backtraces": bt_val.lower() in ["1", "on", "true"] if bt_val else None,
            "memory_limit": mem_lim,
            "post_max_size": post_max,
            "oom_risk": False,
            "oom_details": "",
        }
        if mem_lim and post_max:
            mb = parse_size_bytes(mem_lim)
            pb = parse_size_bytes(post_max)
            if mb != -1 and pb >= mb:
                item["oom_risk"] = True
                item["oom_details"] = f"post_max_size ({post_max}) >= memory_limit ({mem_lim}); OOM parsing trap for CVE-2026-109618"
        findings.append(item)

    # 2. PHP-FPM Binaries
    fpm_patterns = [
        "/usr/sbin/php-fpm*",
        "/usr/local/sbin/php-fpm*",
        "/opt/plesk/php/*/sbin/php-fpm",
        "/opt/php-*/sbin/php-fpm",
        "/opt/php-*/bin/php-fpm",
    ]
    fpm_bins = find_unique_binaries(fpm_patterns)
    for b in fpm_bins:
        ver_str, prog_val, bt_val, mem_lim, post_max = inspect_fpm_binary(b)
        if not ver_str:
            continue
        semver = parse_semver(ver_str)
        build_date = get_build_date(b)
        status, target_ver, desc = apply_build_date(*evaluate_version(semver), build_date)
        item = {
            "type": "fpm",
            "path": b,
            "version": ver_str,
            "build_date": build_date.strftime("%Y-%m-%d") if build_date else None,
            "semver": list(semver) if semver else None,
            "status": status,
            "target_version": target_ver,
            "details": desc,
            "upload_progress_enabled": prog_val.lower() in ["1", "on", "true"],
            "fatal_error_backtraces": bt_val.lower() in ["1", "on", "true"] if bt_val else None,
            "memory_limit": mem_lim,
            "post_max_size": post_max,
            "oom_risk": False,
            "oom_details": "",
        }
        if mem_lim and post_max:
            mb = parse_size_bytes(mem_lim)
            pb = parse_size_bytes(post_max)
            if mb != -1 and pb >= mb:
                item["oom_risk"] = True
                item["oom_details"] = f"post_max_size ({post_max}) >= memory_limit ({mem_lim}); OOM parsing trap for CVE-2026-109618"
        findings.append(item)

    # 3. Apache mod_php
    so_patterns = [
        "/usr/lib/apache2/modules/libphp*.so",
        "/usr/lib64/httpd/modules/libphp*.so",
        "/etc/httpd/modules/libphp*.so",
    ]
    so_files = []
    seen_so = set()
    for pat in so_patterns:
        for f in glob.glob(pat):
            if os.path.isfile(f):
                real = os.path.realpath(f)
                if real not in seen_so:
                    seen_so.add(real)
                    so_files.append(real)

    for so in so_files:
        ver_str = inspect_so_module(so)
        if ver_str:
            semver = parse_semver(ver_str)
            status, target_ver, desc = evaluate_version(semver)
            findings.append({
                "type": "mod_php",
                "path": so,
                "version": ver_str,
                "semver": list(semver) if semver else None,
                "status": status,
                "target_version": target_ver,
                "details": desc,
                "upload_progress_enabled": None,
                "fatal_error_backtraces": None,
                "memory_limit": "",
                "post_max_size": "",
                "oom_risk": False,
                "oom_details": "",
            })
        else:
            findings.append({
                "type": "mod_php",
                "path": so,
                "version": "Unknown",
                "semver": None,
                "status": "CHECK_PACKAGE",
                "target_version": "8.2.35+",
                "details": "Installed Apache PHP module; query package manager (dpkg -S / rpm -qf) for exact version.",
                "upload_progress_enabled": None,
                "fatal_error_backtraces": None,
                "memory_limit": "",
                "post_max_size": "",
                "oom_risk": False,
                "oom_details": "",
            })

    # Summary calculation
    total = len(findings)
    patched = sum(1 for f in findings if f["status"] == "PATCHED")
    vuln_eol = sum(1 for f in findings if f["status"] == "VULNERABLE_EOL")
    vuln_unpatched = sum(1 for f in findings if f["status"] == "VULNERABLE_UNPATCHED")
    total_vuln = vuln_eol + vuln_unpatched
    has_active_progress = sum(1 for f in findings if f.get("upload_progress_enabled") is True)
    has_oom_risk = sum(1 for f in findings if f.get("oom_risk") is True)

    result = {
        "hostname": hostname,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "is_vulnerable": total_vuln > 0,
        "summary": {
            "total_binaries": total,
            "patched": patched,
            "vulnerable": total_vuln,
            "vulnerable_eol": vuln_eol,
            "vulnerable_unpatched": vuln_unpatched,
            "upload_progress_active": has_active_progress,
            "oom_risk_count": has_oom_risk,
        },
        "findings": findings,
    }
    return result

def print_human_report(res):
    print("=" * 80)
    print(" PHP2SHELL VULNERABILITY AUDIT (CVE-2026-109618 & CVE-2026-109619)")
    print(f" Host: {res['hostname']} | Timestamp: {res['timestamp']}")
    print("=" * 80)
    print(f" Binaries Checked: {res['summary']['total_binaries']}")
    print(f" Patched Versions: {res['summary']['patched']}")
    print(f" Vulnerable EOL  : {res['summary']['vulnerable_eol']} (PHP 5.x, 7.x, 8.0, 8.1)")
    print(f" Vulnerable Live : {res['summary']['vulnerable_unpatched']} (PHP 8.2-8.5 needing update)")
    print("-" * 80)

    for f in res["findings"]:
        t = f["type"].upper().ljust(7)
        p = f["path"]
        v = f["version"]
        st = f["status"]
        if st == "PATCHED":
            badge = "[PATCHED]            "
        elif st == "VULNERABLE_EOL":
            badge = "[VULNERABLE - EOL]   "
        elif st == "VULNERABLE_UNPATCHED":
            badge = f"[VULNERABLE < {f['target_version']}]"
        else:
            badge = "[CHECK MANUAL]       "

        if st == "PATCHED" and f.get("details", "").startswith("Patched via backport"):
            badge = "[PATCHED - BACKPORT] "
        built = f" built {f['build_date']}" if f.get("build_date") else ""
        print(f" {t} {badge} {p} ({v}{built})")
        if f.get("upload_progress_enabled") is True:
            print("     ! session.upload_progress.enabled is ON (Immediate Attack Vector)")
        if f.get("fatal_error_backtraces") is True:
            print("     ! fatal_error_backtraces is ON (CVE-2026-109619 UAF Vector)")
        if f.get("oom_risk"):
            print(f"     ! {f.get('oom_details')}")

    print("=" * 80)
    if res["is_vulnerable"]:
        print(" ACTION REQUIRED:")
        print(" 1. For supported branches (PHP 8.2+): Upgrade packages immediately to:")
        print("    PHP >= 8.2.35 | PHP >= 8.3.36 | PHP >= 8.4.27 | PHP >= 8.5.12")
        print(" 2. For legacy EOL versions (PHP 5.x, 7.x, 8.0, 8.1): Apply php2shellfix.sh")
        print("    defensive mitigations, enforce locked pool flags, and isolate systems.")
        print("=" * 80)

if __name__ == "__main__":
    audit_data = run_audit()
    if "--json" in sys.argv or not sys.stdout.isatty():
        print(json.dumps(audit_data, indent=2))
    else:
        print_human_report(audit_data)
