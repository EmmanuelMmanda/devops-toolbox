# DevOps Toolbox

Small, inspectable tools for server inventory and maintenance. Each tool has its own scope and instructions. **Nothing in this repository should be run with `curl | bash` or `irm | iex`; clone it and inspect the tool first.**

## PHP security scan

`tools/php_security_scan.py` is a **read-only, offline** inventory for [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp), announced on 21 October 2026. It supports Linux, cPanel servers, and Windows. It requires Python 3.8+ and only uses the Python standard library.

The scanner checks common PHP binaries, package metadata, running PHP/web process names, cPanel PHP configuration, and IIS FastCGI paths where available. It prints an assessment and next steps. It does **not** update software, restart services, modify files or settings, contact the network, or probe for an exploit. The default output is to the terminal; `--json` prints machine-readable JSON to standard output. The scanner itself never writes a report file.

### Run

Clone this repository to the server, inspect the script, and run from the repository root:

```bash
# Linux or cPanel server
python3 tools/php_security_scan.py
python3 tools/php_security_scan.py --json
```

```powershell
# Windows PowerShell
py -3 .\tools\php_security_scan.py
py -3 .\tools\php_security_scan.py --json
```

No administrator rights are required. Running as an administrator/root can reveal more package or process information, but it is optional. Some Windows servers use `python` rather than `py -3`.

### Reading the result

- `below_upstream_fix` means the observed binary's version precedes PHP's fixed upstream release. A vendor may have backported the fix; check its advisory for **both** CVEs.
- `fixed_upstream` means the observed binary meets the upstream fixed version for its branch.
- On Ubuntu 24.04, the scanner also checks installed PHP 8.3 packages against [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1): `8.3.6-0ubuntu0.24.04.13` is the first fixed Ubuntu package for both CVEs. `below_vendor_fix` means an installed package predates that revision; `fixed_vendor_backport` means it meets or exceeds it.
- `unsupported_upstream_check_vendor` means PHP 8.1 or older. PHP has not published an upstream release for that branch; obtain a vendor-confirmed backport or upgrade.
- `unreadable`, `unknown_branch`, and `insufficient_evidence` require manual follow-up.

The first fixed upstream releases are **8.2.35, 8.3.36, 8.4.27, and 8.5.12**. Source: [PHP security notice](https://www.php.net/).

### Important limits

CLI PHP can differ from the PHP serving a website. Check **each site's actual web PHP version**, including FPM pools, Apache modules, LiteSpeed, containers, and IIS handler mappings. A fixed binary on disk does not prove an old worker has restarted. The scanner only has a built-in vendor backport check for Ubuntu 24.04 PHP 8.3; it cannot find every custom installation or determine whether a server was compromised. A clean scan is an inventory result, **not a security certification**.

After confirming the vendor's patch, restart affected web workers, verify the served version per site, and investigate signs of compromise if the server was exposed before patching.

### Data handling

The tool does not make network requests or send telemetry. Its terminal output can include local executable paths, package versions, and process names. Review it before sharing.

## Future tools

Keep future tools in `tools/`, with a clear statement of whether each one only inspects or also makes changes. This scanner is intentionally inspection only.
