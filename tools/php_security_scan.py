#!/usr/bin/env python3
"""Read-only local inventory for the PHP October 2026 security release.

Standard-library only. Does not need administrator access, use a network, or
write to disk. Findings describe observed evidence, not proof of safety.
"""

import argparse
import datetime as dt
import glob
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path


FIXED = {"8.2": (8, 2, 35), "8.3": (8, 3, 36), "8.4": (8, 4, 27), "8.5": (8, 5, 12)}
CVES = ("CVE-2026-109618", "CVE-2026-109619")
VERSION_RE = re.compile(r"PHP\s+(\d+)\.(\d+)\.(\d+)", re.I)
MAX_BINARIES = 100


def run(argv, timeout=6):
    """Run a fixed, local, read-only inspection command without a shell."""
    try:
        p = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        return p.stdout[:200000] if p.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def version_status(version):
    parts = tuple(int(x) for x in version.split("."))
    branch = ".".join(version.split(".")[:2])
    if branch in FIXED:
        return ("fixed_upstream" if parts >= FIXED[branch] else
                "below_upstream_fix", ".".join(map(str, FIXED[branch])))
    if parts < (8, 2, 0):
        return "unsupported_upstream_check_vendor", None
    return "unknown_branch", None


def candidates(system, context):
    found = []
    path_php = shutil.which("php")
    if path_php:
        found.append(path_php)
    if system == "Windows":
        for line in run(["where.exe", "php.exe"]).splitlines():
            found.append(line.strip())
        found.extend(context["php_processes"])
        found.extend(context["iis_fastcgi_paths"])
        patterns = [r"C:\PHP*\php.exe", r"C:\Program Files\PHP*\php.exe",
                    r"C:\xampp\php\php.exe", r"C:\laragon\bin\php\*\php.exe"]
    else:
        patterns = ["/usr/bin/php[0-9]*", "/usr/local/bin/php[0-9]*",
                    "/opt/cpanel/ea-php*/root/usr/bin/php",
                    "/opt/alt/php*/usr/bin/php"]
    for pattern in patterns:
        found.extend(glob.glob(pattern))
    unique = []
    seen = set()
    for item in found:
        try:
            path = str(Path(item).resolve())
            key = os.path.normcase(path)
            if key not in seen and Path(path).is_file() and os.access(path, os.X_OK):
                seen.add(key)
                unique.append(path)
        except (OSError, RuntimeError):
            pass
        if len(unique) >= MAX_BINARIES:
            break
    return unique


def inspect_binary(path):
    output = run([path, "-v"])
    match = VERSION_RE.search(output)
    if not match:
        return {"path": path, "version": None, "status": "unreadable"}
    version = ".".join(match.groups())
    status, fixed = version_status(version)
    return {"path": path, "version": version, "status": status,
            "first_fixed_upstream": fixed}


def linux_context():
    result = {"distribution": None, "php_packages": [], "php_processes": [],
              "cpanel": {"detected": False, "configured_branches": []}}
    try:
        data = Path("/etc/os-release").read_text(errors="replace")
        match = re.search(r'^PRETTY_NAME="?([^"\n]+)', data, re.M)
        if match:
            result["distribution"] = match.group(1)
    except OSError:
        pass
    if shutil.which("dpkg-query"):
        output = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], timeout=12)
        result["php_packages"] = [line for line in output.splitlines()
                                  if re.match(r"(?:php|libapache2-mod-php|ea-php|alt-php)[\w.+-]*\t", line)][:200]
    elif shutil.which("rpm"):
        output = run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], timeout=12)
        result["php_packages"] = [line for line in output.splitlines()
                                  if re.match(r"(?:php|ea-php|alt-php)[\w.+-]*\t", line)][:200]
    for name in ("php-fpm", "php-cgi", "lsphp", "httpd", "apache2", "frankenphp", "litespeed"):
        output = run(["pgrep", "-x", name]) if shutil.which("pgrep") else ""
        if output.strip():
            result["php_processes"].append(name)
    cpanel_file = Path("/etc/cpanel/ea4/php.conf")
    result["cpanel"]["detected"] = cpanel_file.exists() or Path("/usr/local/cpanel").exists()
    if cpanel_file.exists():
        try:
            data = cpanel_file.read_text(errors="replace")[:1000000]
            result["cpanel"]["configured_branches"] = sorted(set(
                "%s.%s" % (v[0], v[1]) for v in re.findall(r"ea-php(\d\d)", data)))
        except OSError:
            pass
    return result


def windows_context():
    result = {"php_processes": [], "iis_fastcgi_paths": []}
    ps = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if ps:
        command = "Get-CimInstance Win32_Process -Filter \"Name='php-cgi.exe' OR Name='php.exe'\" | Select-Object -ExpandProperty ExecutablePath"
        result["php_processes"] = sorted(set(x.strip() for x in
            run([ps, "-NoProfile", "-NonInteractive", "-Command", command], timeout=12).splitlines() if x.strip()))
    appcmd = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32/inetsrv/appcmd.exe"
    if appcmd.is_file():
        output = run([str(appcmd), "list", "config", "/section:system.webServer/fastCgi"])
        result["iis_fastcgi_paths"] = sorted(set(re.findall(
            r'fullPath="([^"]*php-cgi\.exe)"', output, re.I)))
    return result


def make_report():
    system = platform.system()
    context = windows_context() if system == "Windows" else linux_context() if system == "Linux" else {}
    binaries = [inspect_binary(p) for p in candidates(system, context)]
    statuses = {b["status"] for b in binaries}
    if "below_upstream_fix" in statuses or "unsupported_upstream_check_vendor" in statuses:
        assessment = "potentially_affected_check_vendor_backports"
    elif binaries and statuses == {"fixed_upstream"}:
        assessment = "observed_binaries_fixed_upstream_web_mapping_unverified"
    else:
        assessment = "insufficient_evidence"
    next_steps = []
    if assessment == "potentially_affected_check_vendor_backports":
        next_steps.append("Check the vendor advisory for both CVEs. Update every web-serving PHP branch lacking a confirmed fix.")
    if not binaries:
        next_steps.append("No PHP binary found in common locations. Inspect web-server mappings, containers, and custom installs.")
    if system == "Windows":
        next_steps.append("Confirm IIS Handler Mappings and FastCGI Settings for every site; compare those paths with the binaries above.")
    elif system == "Linux":
        next_steps.append("Confirm each site's actual web PHP version; CLI, FPM, Apache module, LiteSpeed, and containers can differ.")
    next_steps.extend([
        "A package version below the upstream number may contain a vendor backport; package metadata alone cannot prove either CVE is fixed.",
        "After a confirmed patch, restart every affected web worker and verify the version through each served site.",
        "If previously exposed, review logs and investigate signs of compromise; this scan cannot establish whether exploitation occurred."
    ])
    return {"tool": "php-security-scan", "scan_time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "platform": system, "cves": list(CVES), "fixed_upstream": {
                branch: ".".join(map(str, version)) for branch, version in FIXED.items()},
            "assessment": assessment, "binaries": binaries, "context": context,
            "next_steps": next_steps, "limitations": [
                "Read-only local inventory; no network access, file writes, remediation, or exploit test.",
                "Cannot confirm vendor backports or discover every custom installation, container, or domain mapping.",
                "A clean result is not proof that every web request uses patched PHP."
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print structured JSON to stdout")
    args = parser.parse_args()
    report = make_report()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("PHP security inventory (read-only)")
        print("CVEs: " + ", ".join(report["cves"]))
        print("Assessment: " + report["assessment"].replace("_", " "))
        print("Platform: " + report["platform"])
        print("\nObserved PHP binaries:")
        for item in report["binaries"]:
            print("  {}  {}  {}".format(item["version"] or "?", item["status"], item["path"]))
        if not report["binaries"]:
            print("  None found in common locations")
        print("\nLocal context:")
        print(json.dumps(report["context"], indent=2))
        print("\nNext steps:")
        for step in report["next_steps"]:
            print("  - " + step)
        print("\nLimits: " + " ".join(report["limitations"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
