# DevOps Toolbox

Small, inspectable tools for server operators. Each tool states what it reads, what it changes, and where its conclusions stop.

## PHP security check

`tools/php_security_scan.py` checks local evidence for [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp). Normal scans are **read-only and offline**. The optional `--mitigate` mode can update supported Ubuntu PHP packages after two explicit approvals. Python 3.8+ and the standard library are enough.

The default result is a short verdict, relevant evidence, and copyable commands without numbering or inline comments. `--verbose` adds coverage and supporting findings. `--json` is for automation and sharing detailed evidence after review. Terminal color is used only for headings and status on an interactive terminal; all conclusions remain readable without it.

### Run

Clone the repository, review the script, then run it from the repository root:

```bash
git clone https://github.com/EmmanuelMmanda/devops-toolbox.git
cd devops-toolbox
sh tools/php-security-check.sh
sh tools/php-security-check.sh --verbose
```

On Windows PowerShell:

```powershell
git clone https://github.com/EmmanuelMmanda/devops-toolbox.git
cd devops-toolbox
py -3 .\tools\php_security_scan.py
py -3 .\tools\php_security_scan.py --verbose
```

Run as root/Administrator if you need the fullest local process, socket, and configuration inventory. Normal scans do not require elevated privileges. Do not pipe a remote script directly into a shell. The Linux launcher uses `python3` if present. If it is missing, the launcher makes no change and prints Ubuntu commands to review and install Python; other systems should use their vendor's Python package.

### Guided remediation

On an Ubuntu release covered by [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1), with its matching Ubuntu PHP packages, run:

```bash
sudo sh tools/php-security-check.sh --mitigate
```

The tool scans first and checks that installed packages are below [Canonical's fixed revision](https://ubuntu.com/security/notices/USN-8948-1). It shows `apt-get update` and waits for you to type `REFRESH`. After refreshing metadata it rescans, requires a fixed candidate for every affected installed package, checks apt holds and service state, and runs an apt simulation. It shows the exact package upgrades and commands, then waits for `APPLY`. It runs a targeted PHP package upgrade with `--only-upgrade --no-remove`, verifies installed package revisions, restarts only a confirmed active PHP-FPM or Apache service, and rescans. Apt itself may ask further questions. If any check fails, the tool stops and explains what needs manual attention.

The prompts work entirely from the keyboard. Enter alone, any other text, or Ctrl+C cancels; noninteractive sessions cannot approve changes. For plain terminal output, use `--no-color` or set `NO_COLOR`. Redirected output and JSON have no color codes. Commands printed for copying are never colored or prefixed with a shell prompt.

The guarded package path covers Ubuntu 22.04/PHP 8.1, 24.04/PHP 8.3, 26.04/PHP 8.5, and 26.10/PHP 8.5, using the package lines published in Canonical's notice. `--mitigate` does not support cPanel/EasyApache, Windows, containers, or third-party PHP builds. Those scans continue to give guidance, but the tool will not guess a package manager or restart command. No package transaction can guarantee that every site serves the patched runtime; verify each web handler afterward. Package maintainer scripts can have side effects that an apt simulation cannot fully predict.

### Example result

```text
PHP SECURITY CHECK  /  read-only scan
STATUS  ACTION REQUIRED
CVEs    CVE-2026-109618, CVE-2026-109619

FINDINGS
  Web PHP: php8.3-fpm 8.3.6-0ubuntu0.24.04.12 (below first fixed
    8.3.6-0ubuntu0.24.04.13).
  Active local Nginx -> PHP-FPM socket route observed; web ports: 80, 443.
  Apt cache: candidate 8.3.6-0ubuntu0.24.04.12.

NEXT ACTIONS
Guided fix; commands are shown before approval:
  sudo sh tools/php-security-check.sh --mitigate
Check apt yourself:
  sudo apt update
  apt-cache policy php8.3-fpm
If the candidate remains below 8.3.6-0ubuntu0.24.04.13, check apt sources/security pocket.
After patching, check the service and the served PHP runtime for each site.

Source  https://ubuntu.com/security/notices/USN-8948-1
Limits  Local inventory only; no web request or exploit test. Past compromise is unknown.
More    --verbose for evidence  |  --json for automation
```

This is illustrative output, not a claim about your server. Each indented command can be copied as-is. The scanner still checks the package candidate and apt's proposed changes before installing. A PHP CLI version such as `8.3.6` can remain unchanged after Ubuntu backports a security fix; inspect the complete Ubuntu package revision.

### What it checks

- Common PHP binaries and upstream fixed versions: 8.2.35, 8.3.36, 8.4.27, and 8.5.12.
- Installed Ubuntu PHP package revisions against [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1) for the four release and branch pairs listed above. Other distributions and vendor builds require their own advisories.
- Installed packages, local apt candidates and holds, running processes and services, common Nginx/Apache/FPM routing settings, and local listeners on Linux.
- Common PHP binary paths and IIS FastCGI mappings on Windows; common EasyApache paths on cPanel.
- Docker/Podman container listing and small samples of common error logs on Linux. It does not inspect inside containers or print log lines.

When Nginx routes to an FPM socket that a pool configures and a PHP worker listens on, the tool calls this an **active local route**. That is stronger evidence than a CLI version alone, but it is not a live request to a site. Configured routes are reported separately when a listener or worker cannot be confirmed.

### Interpreting the result

`ACTION REQUIRED` means a recognized installed Ubuntu PHP package is below Canonical's first fixed revision. `OBSERVED VERSIONS FIXED` means the observed binaries and recognized vendor packages meet known fixes; it does **not** verify the active web runtime. `REVIEW REQUIRED` means the available evidence cannot settle the vendor patch state. Treat unsupported or custom builds according to their vendor advisory.

After updating, restart the affected PHP web workers, check the service, and verify the served PHP runtime for every site and handler. If the server was exposed before patching, investigate independently: zero counts in sampled logs do not prove that exploitation did not occur.

### Boundaries and privacy

Normal scans never contact a website, create a diagnostic endpoint, change local state, or provide a 100% security guarantee. `--mitigate` refreshes apt metadata, installs approved updates, and restarts confirmed services. The scan may miss custom installation paths, included configuration, Apache modules, LiteSpeed handlers, container internals, and workloads not visible to the current user. A patched file on disk does not prove an old worker has restarted.

The default and verbose reports omit configured site names. `--json` can include local paths, socket names, process details, and container names; review it before sharing. No raw configuration files or log lines are returned. No secrets are intentionally collected.

### Develop

```bash
python3 -m unittest discover -s tests -v
```

Contributions should preserve read-only default scans, require explicit approval for changes, distinguish observed facts from inferences, and include a test for each new vendor rule or routing conclusion. Security advisories and package thresholds must cite the vendor source. See [LICENSE](LICENSE) for the MIT license.
