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

### Platform guides

| Environment | Scan | Update path |
| --- | --- | --- |
| Ubuntu packages covered by USN-8948-1 | Linux launcher | `--mitigate` with two approvals, or follow Canonical's notice manually |
| cPanel / WHM EasyApache 4, including cPanel on Ubuntu | Linux launcher | WHM EasyApache 4 system update; verify every installed EA-PHP branch |
| Windows IIS | PowerShell command above | Install a fixed Windows PHP build and update the actual IIS FastCGI and handler mappings |
| Windows Apache bundles or custom PHP | PowerShell command above | Follow the bundle/vendor update path and verify its PHP binary |
| Other Linux distributions or containers | Run inside each relevant system | Use its vendor advisory and package manager; restart the actual PHP workers |

#### Ubuntu packages

[Canonical's notice](https://ubuntu.com/security/notices/USN-8948-1) gives these **first fixed package revisions** for both CVEs. Check the complete package revision; `php -v` may still show the same upstream version after a backport.

| Ubuntu release | PHP branch | First fixed package revision |
| --- | --- | --- |
| 22.04 | 8.1 | `8.1.2-1ubuntu2.28` |
| 24.04 | 8.3 | `8.3.6-0ubuntu0.24.04.13` |
| 26.04 | 8.5 | `8.5.4-0ubuntu1.5` |
| 26.10 | 8.5 | `8.5.9-0ubuntu2.1` |

Run the normal scan first. If it identifies a supported Ubuntu package below its fixed revision, the guided command above refreshes apt metadata, checks holds and candidates, previews the targeted transaction, and asks twice before changing anything. A fixed package on disk still needs worker and served-site verification. If the server uses cPanel's `ea-php` packages, follow the cPanel path below even when the OS is Ubuntu.

#### cPanel / WHM EasyApache 4

Run the scan as root for the fullest inventory:

```bash
sudo sh tools/php-security-check.sh --verbose
```

The [EasyApache 4 change log, release 25.91](https://docs.cpanel.net/changelogs/easyapache-4-change-log-25/), records fixes for both CVEs. It lists backports for `ea-php74`, `ea-php80`, and `ea-php81`; it updates `ea-php82` to 8.2.35, `ea-php83` to 8.3.36, `ea-php84` to 8.4.27, and `ea-php85` to 8.5.12. For the backported branches, a PHP version string alone cannot prove the package includes the fix. Confirm the installed cPanel package update against that release.

In **WHM → Software → MultiPHP Manager**, identify the PHP branch assigned to each site. Then use **WHM → Software → EasyApache 4 → Run System Update** and review the proposed package changes. cPanel documents this as the supported interface for updating Apache's PHP; `/usr/local/cpanel/scripts/upcp` updates cPanel and much other system software, so it is a broader operation. [cPanel update guide](https://docs.cpanel.net/knowledge-base/general-systems-administration/how-to-update-your-system/), [per-site PHP guide](https://docs.cpanel.net/ea4/php/how-to-locate-and-install-a-php-version-or-extension/).

For a read-only package inventory on RPM-based cPanel servers:

```bash
rpm -qa | grep '^ea-php'
```

On Ubuntu-based cPanel servers:

```bash
dpkg-query -W 'ea-php*'
```

After updating, rescan and verify each site's assigned and served PHP branch. If Apache PHP-FPM is the handler, cPanel documents this restart command; expect a brief service interruption:

```bash
/usr/local/cpanel/scripts/restartsrv_apache_php_fpm --hard
```

LiteSpeed uses `lsphp` instead of cPanel's Apache PHP-FPM service; follow its vendor's worker restart procedure. Third-party or CloudLinux PHP packages need their own vendor advisory. The scanner intentionally refuses `--mitigate` on cPanel. [cPanel PHP-FPM guide](https://docs.cpanel.net/knowledge-base/php-fpm/php-fastcgi-process-manager-php-fpm/).

#### Windows IIS and bundled PHP

Run the scan from an elevated PowerShell session when you need process and IIS configuration visibility:

```powershell
py -3 .\tools\php_security_scan.py --verbose
```

For IIS, inspect both FastCGI registrations and `.php` handler mappings. These commands only read configuration:

```powershell
& "$env:windir\System32\inetsrv\appcmd.exe" list config /section:system.webServer/fastCgi
& "$env:windir\System32\inetsrv\appcmd.exe" list config /section:system.webServer/handlers
```

The PHP path in a handler must point to the intended `php-cgi.exe`; site-specific mappings may differ from global mappings. For IIS FastCGI, PHP recommends the **Non-Thread Safe** Windows build. Obtain a fixed build from the [official PHP for Windows downloads](https://windows.php.net/download/), validate application and extension compatibility, deploy it alongside the old build, update the affected IIS FastCGI and handler paths in IIS Manager, then recycle the affected application pools. Rescan and verify the PHP version served by every site. Avoid a blanket IIS restart when only specific application pools need recycling. [PHP IIS installation guide](https://www.php.net/manual/en/install.windows.iis.php), [Microsoft FastCGI mapping guide](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/fastcgi/).

For official upstream PHP builds, these are the first fixed versions for both CVEs: PHP 8.2.35, 8.3.36, 8.4.27, and 8.5.12. A custom or vendor-backported build needs its vendor's own confirmation; PHP 8.1 and older have no upstream release in this set. [PHP advisories for CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

For XAMPP, Laragon, Apache, or another bundled installation, use the bundle/vendor's update process and verify the binary actually used by its web service. The scanner does not rewrite IIS or bundle configuration and does not offer `--mitigate` on Windows. If Python is absent, install Python 3.8+ through your approved Windows software channel before using this scanner.

#### Other Linux systems and containers

Run the scanner in each PHP-serving container as well as on the host. A host scan lists common Docker/Podman containers but does not inspect their installed PHP. For Debian, RHEL-family distributions, CloudLinux, and custom builds, compare installed packages with the **vendor's** advisory for both CVEs; a lower upstream number may still contain a vendor backport. Update using that vendor's supported channel, restart the workers that serve requests, and verify the served runtime. `--mitigate` stops when it cannot establish a supported Ubuntu package and restart path.

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

The [CI workflow](.github/workflows/test.yml) runs unit tests and a read-only scan on Ubuntu and Windows with two Python versions. It never invokes `--mitigate`. A passing workflow verifies the code paths covered by tests; it does not replace testing on a real cPanel, IIS, or production PHP deployment.

Contributions should preserve read-only default scans, require explicit approval for changes, distinguish observed facts from inferences, and include a test for each new vendor rule or routing conclusion. Security advisories and package thresholds must cite the vendor source. See [LICENSE](LICENSE) for the MIT license.
