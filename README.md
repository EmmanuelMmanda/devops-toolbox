# DevOps Toolbox

Small, inspectable tools for server operators. Each tool states what it reads, what it changes, and where its conclusions stop.

## PHP security check

`tools/php_security_scan.py` checks local evidence for [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp). It is **read-only and offline**. It never installs updates, restarts services, writes a report, sends telemetry, or tests an exploit. Python 3.8+ and the standard library are enough.

The default result is a short verdict, relevant evidence, and commands to consider. `--verbose` adds coverage and supporting findings. `--json` is for automation and sharing detailed evidence after review.

### Run

Clone the repository, review the script, then run it from the repository root:

```bash
git clone https://github.com/EmmanuelMmanda/devops-toolbox.git
cd devops-toolbox
python3 tools/php_security_scan.py
python3 tools/php_security_scan.py --verbose
```

On Windows PowerShell:

```powershell
git clone https://github.com/EmmanuelMmanda/devops-toolbox.git
cd devops-toolbox
py -3 .\tools\php_security_scan.py
py -3 .\tools\php_security_scan.py --verbose
```

Run as root/Administrator if you need the fullest local process, socket, and configuration inventory. The tool does not require elevated privileges. Do not pipe a remote script directly into a shell.

### Example result

```text
PHP security check | read-only
ACTION REQUIRED | CVE-2026-109618, CVE-2026-109619

Web PHP: php8.3-fpm 8.3.6-0ubuntu0.24.04.12 (below first fixed 8.3.6-0ubuntu0.24.04.13).
Active local Nginx -> PHP-FPM socket route observed; web ports: 80, 443.
Apt cache: candidate 8.3.6-0ubuntu0.24.04.12.

Next actions
  1. sudo apt update
  2. apt-cache policy php8.3-fpm
  If the candidate is 8.3.6-0ubuntu0.24.04.13 or newer:
  3. sudo apt upgrade    # review proposed changes before accepting
  4. sudo systemctl restart php8.3-fpm
  5. python3 tools/php_security_scan.py
  If still older: check apt sources/security pocket; do not assume an upgrade will fix it.
  Then check service status and the served PHP runtime for each site.

Evidence: https://ubuntu.com/security/notices/USN-8948-1
Scope: local inventory only; no web request or exploit test. Historical compromise is unknown.
Details: --verbose | Automation: --json
```

This is illustrative output, not a claim about your server. Follow the commands only after checking the package candidate and reviewing apt's proposed changes. A PHP CLI version such as `8.3.6` can remain unchanged after Ubuntu backports a security fix; inspect the complete Ubuntu package revision.

### What it checks

- Common PHP binaries and upstream fixed versions: 8.2.35, 8.3.36, 8.4.27, and 8.5.12.
- Installed Ubuntu 24.04 PHP 8.3 package revisions against [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1). This is the only built-in vendor backport rule. Other distributions and vendor builds require their own advisories.
- Installed packages, local apt candidates and holds, running processes and services, common Nginx/Apache/FPM routing settings, and local listeners on Linux.
- Common PHP binary paths and IIS FastCGI mappings on Windows; common EasyApache paths on cPanel.
- Docker/Podman container listing and small samples of common error logs on Linux. It does not inspect inside containers or print log lines.

When Nginx routes to an FPM socket that a pool configures and a PHP worker listens on, the tool calls this an **active local route**. That is stronger evidence than a CLI version alone, but it is not a live request to a site. Configured routes are reported separately when a listener or worker cannot be confirmed.

### Interpreting the result

`ACTION REQUIRED` means an installed Ubuntu 24.04 PHP 8.3 package is below Canonical's first fixed revision. `OBSERVED VERSIONS FIXED` means the observed binaries and recognized vendor packages meet known fixes; it does **not** verify the active web runtime. `REVIEW REQUIRED` means the available evidence cannot settle the vendor patch state. Treat unsupported or custom builds according to their vendor advisory.

After updating, restart the affected PHP web workers, check the service, and verify the served PHP runtime for every site and handler. If the server was exposed before patching, investigate independently: zero counts in sampled logs do not prove that exploitation did not occur.

### Boundaries and privacy

The scanner never contacts a website, creates a diagnostic endpoint, changes local state, or provides a 100% security guarantee. It may miss custom installation paths, included configuration, Apache modules, LiteSpeed handlers, container internals, and workloads not visible to the current user. A patched file on disk does not prove an old worker has restarted.

The default and verbose reports omit configured site names. `--json` can include local paths, socket names, process details, and container names; review it before sharing. No raw configuration files or log lines are returned. No secrets are intentionally collected.

### Develop

```bash
python3 -m unittest discover -s tests -v
```

Contributions should preserve read-only behavior, distinguish observed facts from inferences, and include a test for each new vendor rule or routing conclusion. Security advisories and package thresholds must cite the vendor source. See [LICENSE](LICENSE) for the MIT license.
