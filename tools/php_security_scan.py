#!/usr/bin/env python3
"""PHP October 2026 security check with optional approved remediation.

Normal scans are read-only and offline. --mitigate can refresh apt metadata,
install supported Ubuntu fixes, and restart known services after approval.
Findings describe observed evidence, not proof of safety. Standard-library only.
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
import textwrap
from pathlib import Path


FIXED = {"8.2": (8, 2, 35), "8.3": (8, 3, 36), "8.4": (8, 4, 27), "8.5": (8, 5, 12)}
CVES = ("CVE-2026-109618", "CVE-2026-109619")
VERSION_RE = re.compile(r"PHP\s+(\d+)\.(\d+)\.(\d+)", re.I)
MAX_BINARIES = 100
UBUNTU_FIXED = {
    ("22.04", "8.1"): "8.1.2-1ubuntu2.28",
    ("24.04", "8.3"): "8.3.6-0ubuntu0.24.04.13",
    ("26.04", "8.5"): "8.5.4-0ubuntu1.5",
    ("26.10", "8.5"): "8.5.9-0ubuntu2.1",
}
UBUNTU_NOTICE = "https://ubuntu.com/security/notices/USN-8948-1"
CPANEL_NOTICE = "https://docs.cpanel.net/changelogs/easyapache-4-change-log-25/"
MAX_CONFIG_MATCHES = 120
WEB_PROCESS_RE = re.compile(r"php|apache|httpd|nginx|litespeed|lsws|caddy|frankenphp", re.I)
PHP_PACKAGE_RE = re.compile(r"(?:php|libapache2-mod-php|ea-php|alt-php)[\w.+-]*$")


def run(argv, timeout=6):
    """Run a fixed, local, read-only inspection command without a shell."""
    try:
        p = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        return p.stdout[:200000] if p.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def probe(argv, timeout=8):
    """Return a bounded result for an inspection command; never invoke a shell."""
    try:
        p = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, check=False)
        return {"ok": p.returncode == 0, "stdout": p.stdout[:200000],
                "truncated": len(p.stdout) > 200000,
                "error": (p.stderr[:300].strip() or "exit_code_{}".format(p.returncode))
                if p.returncode else ""}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "stdout": "", "truncated": False, "error": type(exc).__name__}


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
        found.extend(context.get("iis_handler_paths", []))
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


def inspect_binary(path, context):
    output = run([path, "-v"])
    match = VERSION_RE.search(output)
    if not match:
        return {"path": path, "version": None, "status": "unreadable"}
    version = ".".join(match.groups())
    status, fixed = version_status(version)
    result = {"path": path, "version": version, "status": status,
              "first_fixed_upstream": fixed}
    vendor = context.get("ubuntu_security") or {}
    branch = vendor.get("branch")
    if branch and path == "/usr/bin/php{}".format(branch):
        cli = vendor.get("packages", {}).get("php{}-cli".format(branch))
        if cli and cli["status"] != "unknown":
            result["status"] = "fixed_vendor_backport" if cli["status"] == "fixed" else "below_vendor_fix"
            result["vendor_package"] = "php{}-cli".format(branch)
            result["vendor_package_version"] = cli["installed"]
            result["first_fixed_vendor_package"] = vendor["first_fixed_package"]
    return result


def dpkg_ge(installed, fixed):
    try:
        result = subprocess.run(["dpkg", "--compare-versions", installed, "ge", fixed],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=3, check=False)
        if result.returncode in (0, 1):
            return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def apt_candidates(package_names):
    result = {}
    if not shutil.which("apt-cache"):
        return result
    for name in package_names:
        output = run(["apt-cache", "policy", name])
        match = re.search(r"^\s*Candidate:\s*(\S+)", output, re.M)
        if match:
            result[name] = match.group(1)
    return result


def apt_holds():
    if not shutil.which("apt-mark"):
        return {"status": "unavailable", "php_packages": []}
    check = probe(["apt-mark", "showhold"])
    return {"status": "checked" if check["ok"] else "unavailable",
            "php_packages": [x for x in check["stdout"].splitlines()
                             if PHP_PACKAGE_RE.fullmatch(x.strip())][:100],
            "reason": check["error"]}


def process_inventory():
    """Read process names, executable links and PHP module state from procfs."""
    proc = Path("/proc")
    if not proc.is_dir():
        return {"status": "unavailable", "entries": []}
    grouped = {}
    try:
        pids = [p for p in proc.iterdir() if p.name.isdigit()]
    except OSError:
        return {"status": "unavailable", "entries": []}
    unreadable = 0
    for pid_dir in pids:
        try:
            name = (pid_dir / "comm").read_text(errors="replace").strip()
            if not WEB_PROCESS_RE.search(name):
                continue
            try:
                executable = os.readlink(str(pid_dir / "exe"))
            except OSError:
                executable = None
                unreadable += 1
            module = False
            old_php_mapping = False
            if re.search(r"apache|httpd|php|litespeed|lsws|frankenphp", name, re.I):
                try:
                    with (pid_dir / "maps").open(errors="replace") as maps:
                        for line in maps:
                            lower = line.lower()
                            if "libphp" in lower:
                                module = True
                            if "(deleted)" in lower and "php" in lower:
                                old_php_mapping = True
                except OSError:
                    unreadable += 1
            key = (name, executable, module, old_php_mapping)
            entry = grouped.setdefault(key, {"name": name, "executable": executable,
                                             "php_module_loaded": module,
                                             "deleted_php_mapping": old_php_mapping,
                                             "count": 0, "example_pids": []})
            entry["count"] += 1
            if len(entry["example_pids"]) < 5:
                entry["example_pids"].append(int(pid_dir.name))
        except OSError:
            unreadable += 1
    return {"status": "checked", "entries": sorted(grouped.values(),
            key=lambda x: (-x["count"], x["name"]))[:80],
            "unreadable_process_items": unreadable}


def service_inventory():
    if not shutil.which("systemctl"):
        return {"status": "unavailable", "units": []}
    result = probe(["systemctl", "list-units", "--all", "--type=service",
                    "--no-legend", "--plain"], timeout=12)
    if not result["ok"]:
        return {"status": "unavailable", "reason": result["error"], "units": []}
    units = []
    for line in result["stdout"].splitlines():
        parts = line.lstrip("● ").split()
        if len(parts) >= 4 and WEB_PROCESS_RE.search(parts[0]):
            units.append({"unit": parts[0], "load": parts[1],
                          "active": parts[2], "sub": parts[3]})
    return {"status": "checked", "units": units[:80]}


def config_inventory():
    patterns = {
        "fpm_pools": ["/etc/php/*/fpm/pool.d/*.conf", "/usr/local/etc/php-fpm.d/*.conf",
                      "/opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf"],
        "nginx": ["/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/*",
                  "/etc/nginx/conf.d/*.conf"],
        "apache": ["/etc/apache2/sites-enabled/*", "/etc/apache2/mods-enabled/*",
                   "/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/*.conf"],
    }
    expressions = {
        "fpm_pools": re.compile(r"^\s*(?:\[[^]]+\]|listen\s*=|user\s*=|group\s*=|php_admin_value\[(?:memory_limit|session\.upload_progress\.enabled)\]\s*=)", re.I),
        "nginx": re.compile(r"^\s*fastcgi_pass\s+", re.I),
        "apache": re.compile(r"^\s*(?:SetHandler|ProxyPassMatch|AddHandler|LoadModule\s+php|<FilesMatch)\b", re.I),
    }
    output = {}
    for group, globs in patterns.items():
        paths = sorted({p for pattern in globs for p in glob.glob(pattern)})[:120]
        matches = []
        unreadable = 0
        for path in paths:
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    for number, line in enumerate(handle, 1):
                        if number > 5000 or len(matches) >= MAX_CONFIG_MATCHES:
                            break
                        value = line.strip()
                        if not value or value.startswith(("#", ";")):
                            continue
                        if expressions[group].search(value):
                            # Report only selected routing settings, not full configuration.
                            matches.append({"file": path, "line": number, "setting": value[:250]})
            except OSError:
                unreadable += 1
            if len(matches) >= MAX_CONFIG_MATCHES:
                break
        output[group] = {"files_checked": len(paths), "matches": matches,
                         "unreadable_files": unreadable,
                         "truncated": len(paths) >= 120 or len(matches) >= MAX_CONFIG_MATCHES}
    return output


def container_inventory():
    result = {}
    for engine in ("docker", "podman"):
        if not shutil.which(engine):
            result[engine] = {"status": "unavailable", "containers": []}
            continue
        check = probe([engine, "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}"], timeout=10)
        if check["ok"]:
            items = []
            for line in check["stdout"].splitlines()[:100]:
                parts = line.split("\t", 2)
                if len(parts) == 3:
                    items.append({"id": parts[0], "image": parts[1], "name": parts[2]})
            result[engine] = {"status": "checked", "containers": items}
        else:
            result[engine] = {"status": "unavailable", "reason": check["error"],
                              "containers": []}
    return result


def listener_inventory():
    if not shutil.which("ss"):
        return {"status": "unavailable", "tcp_web": [], "php_unix": []}
    tcp = probe(["ss", "-H", "-ltnp"])
    unix = probe(["ss", "-H", "-lxnp"])
    web = []
    if tcp["ok"]:
        for line in tcp["stdout"].splitlines():
            parts = line.split()
            if len(parts) >= 5 and re.search(r":(?:80|443|8080|8443)$", parts[3]):
                web.append({"local_address": parts[3], "process": parts[-1][:180]})
    sockets = []
    if unix["ok"]:
        for line in unix["stdout"].splitlines():
            if re.search(r"php|fpm|lsphp", line, re.I):
                parts = line.split()
                sockets.append({"socket": next((p for p in parts if p.startswith("/") and
                                                 re.search(r"php|fpm|lsphp", p, re.I)), "unknown"),
                                "process": parts[-1][:180] if parts else ""})
    return {"status": "checked" if tcp["ok"] or unix["ok"] else "unavailable",
            "tcp_web": web[:40], "php_unix": sockets[:40],
            "reason": "" if tcp["ok"] or unix["ok"] else tcp["error"]}


def log_signal_inventory():
    """Count selected PHP crash/error phrases in bounded log tails; never print lines."""
    patterns = ["/var/log/php*-fpm.log", "/var/log/nginx/error.log",
                "/var/log/apache2/error.log", "/var/log/httpd/error_log"]
    paths = sorted({p for pattern in patterns for p in glob.glob(pattern)})[:30]
    checks = [("php_fatal", re.compile(rb"PHP Fatal error", re.I)),
              ("php_memory_exhaustion", re.compile(rb"Allowed memory size.*exhausted|out of memory", re.I)),
              ("php_worker_crash", re.compile(rb"php.*(?:segfault|SIGSEGV|child exited on signal)", re.I))]
    files = []
    for path in paths:
        try:
            with open(path, "rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(0, size - 2_000_000))
                data = handle.read(2_000_000)
            files.append({"path": path, "bytes_sampled": len(data),
                          "tail_only": size > len(data),
                          "signals": {label: len(pattern.findall(data)) for label, pattern in checks}})
        except OSError:
            files.append({"path": path, "status": "unreadable"})
    return {"status": "checked" if paths else "no_common_logs_found", "files": files}


def linux_context():
    result = {"distribution": None, "php_packages": [], "php_processes": [],
              "cpanel": {"detected": False, "configured_branches": []},
              "ubuntu_security": None, "apt_candidates": {},
              "services": {}, "process_inventory": {}, "configuration": {},
              "containers": {}, "listeners": {}, "apt_holds": {}, "log_signals": {}}
    os_id = version_id = None
    try:
        data = Path("/etc/os-release").read_text(errors="replace")
        match = re.search(r'^PRETTY_NAME="?([^"\n]+)', data, re.M)
        if match:
            result["distribution"] = match.group(1)
        os_match = re.search(r'^ID="?([^"\n]+)', data, re.M)
        version_match = re.search(r'^VERSION_ID="?([^"\n]+)', data, re.M)
        os_id = os_match.group(1) if os_match else None
        version_id = version_match.group(1) if version_match else None
    except OSError:
        pass
    if shutil.which("dpkg-query"):
        output = run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Package}\t${Version}\n"], timeout=12)
        for line in output.splitlines():
            parts = line.split("\t", 2)
            if len(parts) == 3 and parts[0].strip() == "ii" and PHP_PACKAGE_RE.fullmatch(parts[1]):
                result["php_packages"].append(parts[1] + "\t" + parts[2])
        result["php_packages"] = result["php_packages"][:200]
    elif shutil.which("rpm"):
        output = run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], timeout=12)
        result["php_packages"] = [line for line in output.splitlines()
                                  if re.match(r"(?:php|ea-php|alt-php)[\w.+-]*\t", line)][:200]
    ubuntu_branch = next((branch for release, branch in UBUNTU_FIXED
                          if os_id == "ubuntu" and release == version_id), None)
    if ubuntu_branch and shutil.which("dpkg"):
        package_versions = dict(line.split("\t", 1) for line in result["php_packages"] if "\t" in line)
        fixed = UBUNTU_FIXED[(version_id, ubuntu_branch)]
        packages = {}
        for name, installed in package_versions.items():
            if (re.fullmatch(r"php{}(?:-[\w.+-]+)?|libapache2-mod-php{}".format(
                    re.escape(ubuntu_branch), re.escape(ubuntu_branch)), name)
                    and installed.startswith(ubuntu_branch + ".")):
                source_line = re.escape(fixed.rsplit(".", 1)[0]) + r"(?:\.\d+)?"
                ge = dpkg_ge(installed, fixed) if re.fullmatch(source_line, installed) else None
                packages[name] = {"installed": installed,
                                  "status": "unknown" if ge is None else "fixed" if ge else "below_fix"}
        result["ubuntu_security"] = {"release": version_id, "branch": ubuntu_branch,
                                     "notice": UBUNTU_NOTICE,
                                     "first_fixed_package": fixed, "packages": packages}
    branch_for_apt = ubuntu_branch or "8.3"
    result["apt_candidates"] = apt_candidates(["php{}-cli".format(branch_for_apt),
                                                 "php{}-fpm".format(branch_for_apt),
                                                 "php{}-common".format(branch_for_apt),
                                                 "libapache2-mod-php{}".format(branch_for_apt)])
    result["apt_holds"] = apt_holds()
    result["services"] = service_inventory()
    result["process_inventory"] = process_inventory()
    result["php_processes"] = sorted({entry["name"] for entry in
                                      result["process_inventory"].get("entries", [])
                                      if re.search(r"php|lsphp", entry["name"], re.I)})
    result["configuration"] = config_inventory()
    result["containers"] = container_inventory()
    result["listeners"] = listener_inventory()
    result["log_signals"] = log_signal_inventory()
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
    result = {"php_processes": [], "iis_fastcgi_paths": [], "iis_handler_paths": []}
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
        handlers = run([str(appcmd), "list", "config", "/section:system.webServer/handlers"])
        result["iis_handler_paths"] = sorted(set(re.findall(
            r'scriptProcessor="([^"]*?php-cgi\.exe)(?:\|[^"]*)?"', handlers, re.I)))
    return result


def web_route(context):
    """Correlate local Nginx, FPM, and socket evidence without requesting a site."""
    config = context.get("configuration", {})
    nginx = [m["setting"] for m in config.get("nginx", {}).get("matches", [])]
    pools = [m["setting"] for m in config.get("fpm_pools", {}).get("matches", [])]
    routes = set()
    for setting in nginx:
        match = re.search(r"\bfastcgi_pass\s+unix:([^;\s]+)", setting, re.I)
        if match:
            routes.add(match.group(1))
    pool_sockets = set()
    for setting in pools:
        match = re.match(r"listen\s*=\s*([^;\s]+)", setting, re.I)
        if match and match.group(1).startswith("/"):
            pool_sockets.add(match.group(1))
    live_sockets = {item["socket"] for item in context.get("listeners", {}).get("php_unix", [])}
    services = {item["unit"]: item["active"] for item in context.get("services", {}).get("units", [])}
    processes = {item["name"] for item in context.get("process_inventory", {}).get("entries", [])}
    matched = sorted(routes & pool_sockets)
    active = bool("nginx" in processes and any("php-fpm" in p for p in processes))
    live = sorted(set(matched) & live_sockets)
    status = "active_local_route" if live and active else "configured_route" if matched else "unconfirmed"
    ports = sorted({re.search(r":(80|443|8080|8443)$", item["local_address"]).group(1)
                    for item in context.get("listeners", {}).get("tcp_web", [])
                    if re.search(r":(80|443|8080|8443)$", item["local_address"])})
    return {"status": status, "matched_sockets": matched, "listening_sockets": live,
            "web_ports": ports, "nginx_active": services.get("nginx.service") == "active" or "nginx" in processes,
            "fpm_active": any(name.startswith("php") and "fpm" in name and state == "active"
                              for name, state in services.items()) or any("php-fpm" in p for p in processes)}


def make_report():
    system = platform.system()
    context = windows_context() if system == "Windows" else linux_context() if system == "Linux" else {}
    binaries = [inspect_binary(p, context) for p in candidates(system, context)]
    statuses = {b["status"] for b in binaries}
    ubuntu = context.get("ubuntu_security") or {}
    vendor_states = {p["status"] for p in ubuntu.get("packages", {}).values()}
    if "below_fix" in vendor_states or "below_vendor_fix" in statuses:
        assessment = "ubuntu_packages_below_published_fix"
    elif "below_upstream_fix" in statuses or "unsupported_upstream_check_vendor" in statuses:
        assessment = "potentially_affected_check_vendor_backports"
    elif binaries and statuses.issubset({"fixed_upstream", "fixed_vendor_backport"}) and "unknown" not in vendor_states:
        assessment = "observed_binaries_fixed_or_vendor_patched_web_mapping_unverified"
    else:
        assessment = "insufficient_evidence"
    processes = context.get("process_inventory", {}).get("entries", [])
    config = context.get("configuration", {})
    running_containers = sum(len(v.get("containers", [])) for v in
                             context.get("containers", {}).values())
    web_evidence = {
        "running_web_processes": sorted({p["name"] for p in processes
            if re.search(r"apache|httpd|nginx|litespeed|lsws|caddy|frankenphp", p["name"], re.I)}),
        "running_php_processes": (sorted({p["name"] for p in processes
            if re.search(r"php|lsphp", p["name"], re.I)}) if system == "Linux"
            else context.get("php_processes", [])),
        "running_php_web_workers": sorted({p["name"] for p in processes
            if re.search(r"php-fpm|php-cgi|lsphp|frankenphp", p["name"], re.I)}),
        "apache_php_module_observed": any(p["php_module_loaded"] for p in processes),
        "old_php_mappings_observed": any(p["deleted_php_mapping"] for p in processes),
        "fpm_pool_files_found": config.get("fpm_pools", {}).get("files_checked", 0),
        "web_handler_matches": (sum(1 for group in ("nginx", "apache") for m in
                                   config.get(group, {}).get("matches", [])
                                   if re.search(r"fastcgi_pass|SetHandler|ProxyPassMatch|AddHandler|LoadModule", m["setting"], re.I))
                                   if system == "Linux" else len(context.get("iis_handler_paths", []))),
        "running_containers": running_containers,
        "web_tcp_listeners": len(context.get("listeners", {}).get("tcp_web", [])),
        "php_unix_listeners": len(context.get("listeners", {}).get("php_unix", [])),
    }
    coverage = []
    if system == "Linux":
        coverage = [
            {"check": "installed_packages", "status": "checked" if shutil.which("dpkg-query") or shutil.which("rpm") else "unavailable"},
            {"check": "apt_candidates", "status": "checked" if shutil.which("apt-cache") else "unavailable",
             "note": "Uses local apt metadata; does not refresh repositories."},
            {"check": "apt_package_holds", "status": context["apt_holds"].get("status", "unavailable")},
            {"check": "running_processes", "status": context["process_inventory"].get("status", "unavailable")},
            {"check": "systemd_services", "status": context["services"].get("status", "unavailable")},
            {"check": "common_web_and_fpm_config", "status": "partial" if any(
                v["unreadable_files"] or v["truncated"] for v in config.values()) else "checked",
             "note": "Only common config locations and selected routing directives are inspected."},
            {"check": "container_listing", "status": "checked" if any(
                v["status"] == "checked" for v in context["containers"].values()) else "unavailable",
             "note": "Container internals are not inspected."},
            {"check": "local_listeners", "status": context["listeners"].get("status", "unavailable")},
            {"check": "common_error_log_tails", "status": context["log_signals"].get("status", "unavailable"),
             "note": "Counts selected error phrases in up to 2 MB per log; no log lines are printed."},
            {"check": "live_web_request", "status": "not_performed",
             "note": "The scanner creates no web endpoint and sends no network request."},
        ]
    elif system == "Windows":
        coverage = [
            {"check": "common_php_binaries", "status": "checked"},
            {"check": "iis_fastcgi_paths", "status": "checked" if Path(
                os.environ.get("WINDIR", r"C:\Windows"), "System32", "inetsrv", "appcmd.exe").is_file()
                else "unavailable"},
            {"check": "iis_php_handler_paths", "status": "checked" if Path(
                os.environ.get("WINDIR", r"C:\Windows"), "System32", "inetsrv", "appcmd.exe").is_file()
                else "unavailable"},
            {"check": "running_php_processes", "status": "checked" if shutil.which("powershell.exe") or shutil.which("pwsh.exe") else "unavailable"},
            {"check": "vendor_package_provenance", "status": "not_performed"},
            {"check": "live_web_request", "status": "not_performed"},
        ]
    next_steps = []
    if assessment == "ubuntu_packages_below_published_fix":
        next_steps.append("Ubuntu USN-8948-1 fixes both CVEs in PHP {} package {}. Update installed PHP packages to at least this revision.".format(
            ubuntu["branch"], ubuntu["first_fixed_package"]))
        held = context.get("apt_holds", {}).get("php_packages", [])
        if held:
            next_steps.append("PHP packages are held by apt: {}. Review these holds before updating.".format(", ".join(held)))
        candidate = context.get("apt_candidates", {}).get("php{}-fpm".format(ubuntu["branch"])) or context.get("apt_candidates", {}).get("php{}-cli".format(ubuntu["branch"]))
        if candidate:
            ge = dpkg_ge(candidate, ubuntu["first_fixed_package"])
            if ge is False:
                next_steps.append("Local apt metadata does not yet offer the fixed package. Refresh apt metadata and check enabled Ubuntu security repositories.")
            elif ge is True:
                next_steps.append("Local apt metadata offers a fixed PHP package; install updates during a maintenance window.")
    if assessment == "potentially_affected_check_vendor_backports":
        next_steps.append("Check the vendor advisory for both CVEs. Update every web-serving PHP branch lacking a confirmed fix.")
    if not binaries:
        next_steps.append("No local PHP binary was found in common paths; this inventory cannot classify an installed runtime.")
    if web_evidence["old_php_mappings_observed"]:
        next_steps.append("A running worker maps a deleted PHP file. Restart that worker after updating its package.")
    log_files = context.get("log_signals", {}).get("files", [])
    if any(sum(item.get("signals", {}).values()) > 0 for item in log_files):
        next_steps.append("The sampled error logs contain PHP crash or fatal-error signals. Investigate the counted logs; these signals alone do not establish exploitation.")
    verification_gaps = ["The actual PHP version served by each website was not measured: this scan sends no HTTP request and creates no web endpoint.",
                         "Historical exploitation cannot be ruled out by inventory or bounded log samples."]
    if system == "Linux":
        if not web_evidence["running_php_web_workers"] and not web_evidence["apache_php_module_observed"]:
            verification_gaps.append("No active PHP web worker was observed. PHP could be CLI-only, stopped, in a container, or outside inspected paths.")
        if running_containers:
            verification_gaps.append("Container names were listed, but installed PHP inside containers was not inspected.")
        if not web_evidence["web_handler_matches"]:
            verification_gaps.append("No PHP web handler was found in the common Nginx/Apache config locations.")
    elif system == "Windows" and not context.get("iis_handler_paths"):
        verification_gaps.append("No global IIS PHP handler was observed; per-site handlers or bundled PHP installations may exist.")
    return {"tool": "php-security-scan", "scan_time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "platform": system, "cves": list(CVES), "fixed_upstream": {
                branch: ".".join(map(str, version)) for branch, version in FIXED.items()},
            "assessment": assessment, "binaries": binaries, "context": context,
            "web_evidence": web_evidence, "web_route": web_route(context) if system == "Linux" else None,
            "coverage": coverage,
            "next_steps": next_steps, "verification_gaps": verification_gaps,
            "limitations": [
                "Read-only local inventory; no network access, file writes, remediation, or exploit test.",
                "Built-in vendor package checks cover only the Ubuntu release/branch pairs listed in USN-8948-1; other vendor backports require manual verification.",
                "Cannot discover every custom installation, container runtime, include path, or domain mapping.",
                "Cannot prove absence of compromise or reach 100% certainty from local inventory alone.",
                "A clean result is not proof that every web request uses patched PHP."
            ]}


def terminal_color_enabled():
    """Use decoration only on an interactive terminal that allows color."""
    return (sys.stdout.isatty() and "NO_COLOR" not in os.environ
            and os.environ.get("TERM", "") != "dumb")


def style(value, code, color=False):
    return "\033[{}m{}\033[0m".format(code, value) if color else value


def wrap_report_lines(lines):
    width = max(60, min(96, shutil.get_terminal_size((80, 24)).columns))
    output = []
    for line in lines:
        command = line.startswith("  ") and line.strip().startswith((
            "sudo ", "apt-cache ", "apt-get ", "python3 ", "systemctl ", "sh "))
        if command or len(line) <= width:
            output.append(line)
        else:
            indent = "  " if line.startswith("  ") else ""
            output.append(textwrap.fill(line.strip(), width=width, initial_indent=indent,
                                        subsequent_indent=indent + "  ",
                                        break_long_words=False, break_on_hyphens=False))
    return "\n".join(output)


def render_report(report, verbose=False, color=False, guided=False):
    """Human-readable result; omit hostnames and raw inventory by default."""
    context = report["context"]
    ubuntu = context.get("ubuntu_security") or {}
    cpanel = context.get("cpanel") or {}
    route = report.get("web_route") or {}
    affected = report["assessment"] == "ubuntu_packages_below_published_fix"
    fixed = report["assessment"] == "observed_binaries_fixed_or_vendor_patched_web_mapping_unverified"
    heading = "ACTION REQUIRED" if affected else "OBSERVED VERSIONS FIXED" if fixed else "REVIEW REQUIRED"
    status_color = "1;31" if affected else "1;32" if fixed else "1;33"
    lines = [style("PHP SECURITY CHECK", "1;36", color) + "  /  read-only scan",
             "STATUS  " + style(heading, status_color, color),
             "CVEs    " + ", ".join(CVES), "", style("FINDINGS", "1;36", color)]
    if ubuntu.get("packages"):
        packages = ubuntu["packages"]
        web_packages = [(name, item) for name, item in packages.items()
                        if name.endswith("-fpm") or name.startswith("libapache2-mod-php")]
        selected = web_packages or [(name, item) for name, item in packages.items() if name.endswith("-cli")]
        if selected:
            name, item = selected[0]
            label = "Web PHP" if web_packages and route.get("status") == "active_local_route" else "PHP package"
            lines.append("  {}: {} {} ({}).".format(label, name, item["installed"],
                         "below first fixed {}".format(ubuntu["first_fixed_package"])
                         if item["status"] == "below_fix" else
                         "meets first fixed {}".format(ubuntu["first_fixed_package"])
                         if item["status"] == "fixed" else "fix status unknown"))
        if len({p["status"] for p in packages.values()}) > 1:
            lines.append("  Installed PHP {} packages have mixed fix status; inspect --verbose.".format(ubuntu["branch"]))
    elif report["binaries"]:
        for item in report["binaries"][:3]:
            lines.append("  PHP {}: {}.".format(item.get("version") or "unknown", item["status"].replace("_", " ")))
        if len(report["binaries"]) > 3:
            lines.append("  {} more binaries; inspect --verbose.".format(len(report["binaries"]) - 3))
    else:
        lines.append("  No PHP binary found in common locations.")
    if route.get("status") == "active_local_route":
        lines.append("  Active local Nginx -> PHP-FPM socket route observed; web ports: {}.".format(
            ", ".join(route["web_ports"]) if route["web_ports"] else "not observed"))
    elif route.get("status") == "configured_route":
        lines.append("  Nginx and FPM socket configuration match; active route not confirmed.")
    elif report["web_evidence"].get("running_php_web_workers"):
        lines.append("  PHP web workers observed; exact request route not confirmed.")
    if ubuntu:
        branch = ubuntu["branch"]
        candidate = context.get("apt_candidates", {}).get("php{}-fpm".format(branch)) or context.get("apt_candidates", {}).get("php{}-cli".format(branch))
        lines.append("  Apt cache: {}.".format("candidate " + candidate if candidate else "candidate unavailable"))
        holds = context.get("apt_holds", {}).get("php_packages", [])
        if holds:
            lines.append("  Apt holds: {}.".format(", ".join(holds)))
    if cpanel.get("detected"):
        branches = cpanel.get("configured_branches", [])
        lines.append("  cPanel/EasyApache 4 detected{}.".format(
            "; configured branches: " + ", ".join(branches) if branches else ""))
        lines.append("  EasyApache 4 release 25.91 documents fixes for both CVEs; confirm each installed EA-PHP package.")
    if report["platform"] == "Windows":
        handlers = context.get("iis_handler_paths", [])
        fastcgi = context.get("iis_fastcgi_paths", [])
        lines.append("  IIS PHP handlers observed: {}; FastCGI registrations: {}.".format(
            len(handlers), len(fastcgi)))
        if handlers and not set(handlers).issubset(set(fastcgi)):
            lines.append("  Some IIS PHP handlers do not match an observed FastCGI registration; inspect IIS configuration.")
    if not guided:
        lines.extend(["", style("NEXT ACTIONS", "1;36", color)])
    if cpanel.get("detected"):
        if not guided:
            lines.append("  In WHM: EasyApache 4 > Run System Update; review the changes.")
            lines.append("  In WHM: MultiPHP Manager; check the PHP branch for every site.")
            lines.append("  Compare installed EA-PHP packages with the EasyApache 4 25.91 change log.")
            if ubuntu and any(p["status"] == "below_fix" for p in ubuntu.get("packages", {}).values()):
                lines.append("  Separate Ubuntu PHP packages also need their own vendor update.")
            lines.append("  Restart affected PHP workers, rescan, and verify served PHP per site.")
    elif affected and ubuntu:
        branch = ubuntu["branch"]
        fpm_name = "php{}-fpm".format(branch)
        apache_name = "libapache2-mod-php{}".format(branch)
        package_to_check = (fpm_name if fpm_name in ubuntu["packages"] else
                            apache_name if apache_name in ubuntu["packages"] else
                            "php{}-cli".format(branch))
        if not guided:
            lines.append("Guided fix; commands are shown before approval:")
            lines.append("  sudo sh tools/php-security-check.sh --mitigate")
            lines.append("Check apt yourself:")
            lines.extend(["  sudo apt update", "  apt-cache policy " + package_to_check])
            lines.append("If the candidate remains below {}, check apt sources/security pocket.".format(
                ubuntu["first_fixed_package"]))
            lines.append("After patching, check the service and the served PHP runtime for each site.")
    elif fixed:
        if not guided:
            lines.append("  Confirm affected web workers restarted after the package update.")
            lines.append("  Verify the served PHP runtime for each site, including containers and other handlers.")
    elif report["platform"] == "Windows":
        if not guided:
            lines.append("  Check IIS FastCGI and PHP handler paths, or your bundled server's PHP path.")
            lines.append("  Install a vendor-confirmed fixed PHP build; recycle affected workers and rescan.")
            lines.append("  Verify the PHP runtime served by each site.")
    else:
        if not guided:
            lines.append("  Check the PHP/vendor advisories for both CVEs and update each affected web runtime.")
            lines.append("  Trace each web handler to its PHP runtime; verify the patch and restart affected workers.")
    source = CPANEL_NOTICE if cpanel.get("detected") else ubuntu.get("notice") or "https://www.php.net/"
    lines.extend(["", "Source  " + source])
    if cpanel.get("detected") and ubuntu and any(p["status"] == "below_fix" for p in ubuntu.get("packages", {}).values()):
        lines.append("Source  " + ubuntu["notice"])
    lines.append("Limits  Local inventory only; no web request or exploit test. Past compromise is unknown.")
    if not guided:
        lines.append("More    --verbose for evidence  |  --json for automation")
    if verbose:
        lines.extend(["", style("EVIDENCE AND COVERAGE", "1;36", color), "Binaries:"])
        for item in report["binaries"]:
            lines.append("  {} | {} | {}".format(item.get("version") or "?", item["status"], item["path"]))
        if not report["binaries"]:
            lines.append("  none found")
        if ubuntu:
            lines.append("Ubuntu packages:")
            for name, item in sorted(ubuntu["packages"].items()):
                lines.append("  {} {} {}".format(name, item["installed"], item["status"]))
            lines.append("Apt candidates (local cache):")
            for name, version in sorted(context.get("apt_candidates", {}).items()):
                lines.append("  {} {}".format(name, version))
        if route:
            lines.append("Matched FPM sockets: {}".format(len(route.get("matched_sockets", []))))
            lines.append("Listening matched sockets: {}".format(len(route.get("listening_sockets", []))))
        lines.append("Web workers: {}".format(", ".join(report["web_evidence"].get("running_php_web_workers", [])) or "none observed"))
        lines.append("Coverage:")
        for item in report["coverage"]:
            lines.append("  {}: {}".format(item["check"], item["status"]))
        lines.append("Remaining gaps:")
        for gap in report["verification_gaps"]:
            lines.append("  - " + gap)
        lines.append("Raw structured evidence is available with --json; review local paths before sharing.")
    return wrap_report_lines(lines)


def mitigation_plan(report):
    """Return a narrow Ubuntu package transaction or a reason to stop."""
    if report["platform"] != "Linux":
        return None, "Guided remediation currently supports listed Ubuntu PHP packages only."
    if report["context"].get("cpanel", {}).get("detected"):
        return None, "cPanel/EasyApache manages PHP here; use the cPanel update path."
    ubuntu = report["context"].get("ubuntu_security") or {}
    release, branch = ubuntu.get("release"), ubuntu.get("branch")
    if (release, branch) not in UBUNTU_FIXED or not ubuntu.get("packages"):
        return None, "No supported Ubuntu PHP package set was found."
    packages = ubuntu["packages"]
    if any(item["status"] == "unknown" for item in packages.values()):
        return None, "Installed package status could not be verified."
    if not any(item["status"] == "below_fix" for item in packages.values()):
        return None, "The supported installed packages already meet the published fix."
    if report["context"].get("apt_holds", {}).get("status") != "checked":
        return None, "Apt holds could not be checked."
    if report["context"]["apt_holds"].get("php_packages"):
        return None, "PHP package holds need manual review."
    if not all(shutil.which(cmd) for cmd in ("apt-get", "apt-cache", "dpkg", "systemctl")):
        return None, "Required apt, dpkg, or systemctl command is unavailable."
    services = report["context"].get("services", {})
    if services.get("status") != "checked":
        return None, "Service state could not be checked; worker restart is uncertain."
    active = {item["unit"] for item in services.get("units", []) if item["active"] == "active"}
    restart = []
    fpm_name = "php{}-fpm".format(branch)
    fpm_unit = fpm_name + ".service"
    if fpm_unit in active and fpm_name in packages:
        restart.append(fpm_unit)
    if "apache2.service" in active and "libapache2-mod-php{}".format(branch) in packages:
        restart.append("apache2.service")
    workers = report["web_evidence"].get("running_php_web_workers", [])
    if workers and not restart:
        return None, "A PHP web worker is running but its restart service is not confirmed."
    if report["web_evidence"].get("apache_php_module_observed") and "apache2.service" not in restart:
        return None, "An Apache PHP module is active but its restart service is not confirmed."
    return {"packages": sorted(name for name, item in packages.items() if item["status"] == "below_fix"),
            "restart_units": restart,
            "first_fixed": ubuntu["first_fixed_package"], "release": release,
            "branch": branch}, None


def approve(label):
    if not sys.stdin.isatty():
        print("Stopped: approval requires an interactive terminal.")
        return False
    try:
        return input("Type {} and press Enter (anything else cancels): ".format(label)).strip() == label
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return False


def execute(argv):
    """Run a displayed command directly; leave apt and service output visible."""
    print("\nRunning:\n  " + " ".join(argv), flush=True)
    try:
        return subprocess.call(argv)
    except OSError as exc:
        print("Failed to start {}: {}".format(argv[0], exc))
        return 1


def fixed_candidate(package, fixed):
    candidate = apt_candidates([package]).get(package)
    # Keep automatic installs on the exact source package revision line from the notice.
    if not candidate or not re.fullmatch(re.escape(fixed.rsplit(".", 1)[0]) + r"\.\d+", candidate):
        return None
    return candidate if dpkg_ge(candidate, fixed) is True else None


def simulation_safe(output, packages, fixed):
    """Require every vulnerable target to be upgraded to a fixed revision."""
    if re.search(r"^Remv\s", output, re.M):
        return False, "Apt proposes a removal."
    upgrades = {}
    for line in output.splitlines():
        match = re.match(r"^Inst\s+(\S+)\s+.*?\((\S+)", line)
        if match:
            upgrades[match.group(1)] = match.group(2)
    for name, installed in packages.items():
        if installed["status"] == "below_fix":
            version = upgrades.get(name)
            if not version or dpkg_ge(version, fixed) is not True:
                return False, "Apt does not plan a fixed upgrade for {}.".format(name)
    return True, upgrades


def mitigate(initial, color=False):
    """Two approvals: refresh metadata, then apply a checked PHP-only transaction."""
    print(style("GUIDED REMEDIATION", "1;36", color) + "  /  two approvals required\n")
    print(render_report(initial, color=color, guided=True))
    plan, reason = mitigation_plan(initial)
    if reason:
        print("\nGuided remediation stopped: " + reason)
        return 2
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        print("\nGuided remediation needs root. Run: sudo python3 tools/php_security_scan.py --mitigate")
        return 2
    print("\n" + style("STEP 1 OF 2  REFRESH PACKAGE LISTS", "1;36", color))
    print("This updates apt metadata. It does not install packages.\nCommand:")
    print("  apt-get update")
    if not approve("REFRESH"):
        print("Cancelled. No package lists were refreshed by this run.")
        return 2
    if execute(["apt-get", "update"]) != 0:
        print("Apt metadata refresh failed; nothing was installed.")
        return 3
    current = make_report()
    plan, reason = mitigation_plan(current)
    if reason:
        print("Guided remediation stopped after refresh: " + reason)
        return 2
    candidates_by_name = {name: fixed_candidate(name, plan["first_fixed"])
                          for name in plan["packages"]}
    missing = [name for name, version in candidates_by_name.items() if not version]
    if missing:
        print("No confirmed fixed apt candidate for: {}. Nothing was installed.".format(", ".join(missing)))
        return 2
    package_specs = ["{}={}".format(name, candidates_by_name[name]) for name in plan["packages"]]
    command = ["apt-get", "--no-remove", "--only-upgrade", "install"] + package_specs
    simulation = probe(["apt-get", "--simulate"] + command[1:], timeout=45)
    if not simulation["ok"] or simulation["truncated"]:
        print("Apt simulation could not be fully checked: {}. Nothing was installed.".format(
            "output too large" if simulation["truncated"] else simulation["error"]))
        return 3
    safe, detail = simulation_safe(simulation["stdout"], current["context"]["ubuntu_security"]["packages"], plan["first_fixed"])
    if not safe:
        print("Apt simulation stopped remediation: {} Nothing was installed.".format(detail))
        return 2
    print("\n" + style("STEP 2 OF 2  REVIEW AND APPLY", "1;36", color))
    print("Apt simulation proposes:")
    for name, version in sorted(detail.items()):
        print("  {} -> {}".format(name, version))
    print("Commands after approval:")
    print("  " + " ".join(command))
    for unit in plan["restart_units"]:
        print("  systemctl restart " + unit)
    print("  python3 tools/php_security_scan.py")
    print("Apt may also run package maintainer scripts; the simulation cannot show every side effect.")
    if not approve("APPLY"):
        print("Cancelled. Apt metadata was refreshed; no packages were installed by this run.")
        return 2
    if execute(command) != 0:
        print("Apt did not complete. Inspect its output and package state; workers were not restarted.")
        return 3
    after_install = make_report()
    installed = (after_install["context"].get("ubuntu_security") or {}).get("packages", {})
    if any(installed.get(name, {}).get("status") != "fixed" for name in plan["packages"]):
        print("Package verification failed. Workers were not restarted; inspect installed versions.")
        return 3
    for unit in plan["restart_units"]:
        if execute(["systemctl", "restart", unit]) != 0:
            print("Restart failed. Check the service and resolve it before considering the patch complete.")
            return 3
    final = make_report()
    print("\n" + style("POST-CHANGE SCAN", "1;36", color) + "\n" + render_report(final, color=color, guided=True))
    if any((final["context"].get("ubuntu_security") or {}).get("packages", {}).get(name, {}).get("status") != "fixed"
           for name in plan["packages"]):
        return 3
    if any(unit not in {item["unit"] for item in final["context"].get("services", {}).get("units", [])
                        if item["active"] == "active"} for unit in plan["restart_units"]):
        print("A restarted service is not active. Investigate before declaring success.")
        return 3
    print("\n" + style("PACKAGE AND SERVICE CHECKS PASSED", "1;32", color))
    print("Verify served PHP for each site; exposure history remains unknown.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--verbose", action="store_true", help="Show supporting evidence and coverage")
    output.add_argument("--json", action="store_true", help="Print structured JSON for automation")
    output.add_argument("--mitigate", action="store_true", help="Guide an approved Ubuntu PHP package update")
    parser.add_argument("--no-color", action="store_true", help="Disable terminal colors")
    args = parser.parse_args()
    report = make_report()
    color = terminal_color_enabled() and not args.no_color
    if args.mitigate:
        return mitigate(report, color)
    print(json.dumps(report, indent=2) if args.json else render_report(report, args.verbose, color))
    return 0


if __name__ == "__main__":
    sys.exit(main())
