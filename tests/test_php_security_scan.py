import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "php_security_scan.py"
SPEC = importlib.util.spec_from_file_location("php_security_scan", SCRIPT)
scan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scan)


def ubuntu_context(package_status):
    version = "8.3.6-0ubuntu0.24.04." + ("13" if package_status == "fixed" else "12")
    return {
        "ubuntu_security": {"release": "24.04", "notice": scan.UBUNTU_NOTICE,
            "first_fixed_package": scan.UBUNTU_FIXED[("24.04", "8.3")],
            "packages": {"php8.3-cli": {"installed": version, "status": package_status}}},
        "apt_candidates": {}, "process_inventory": {"status": "checked", "entries": []},
        "services": {"status": "checked", "units": []},
        "configuration": {key: {"files_checked": 0, "matches": [], "unreadable_files": 0,
                               "truncated": False} for key in ("fpm_pools", "nginx", "apache")},
        "containers": {"docker": {"status": "unavailable", "containers": []},
                       "podman": {"status": "unavailable", "containers": []}},
        "listeners": {"status": "unavailable", "tcp_web": [], "php_unix": []},
        "apt_holds": {"status": "checked", "php_packages": []},
        "log_signals": {"status": "no_common_logs_found", "files": []},
    }


class SecurityScanTests(unittest.TestCase):
    def test_upstream_boundary(self):
        self.assertEqual(scan.version_status("8.3.35")[0], "below_upstream_fix")
        self.assertEqual(scan.version_status("8.3.36")[0], "fixed_upstream")

    def test_ubuntu_backport_changes_binary_verdict(self):
        with patch.object(scan, "run", return_value="PHP 8.3.6 (cli)"):
            old = scan.inspect_binary("/usr/bin/php8.3", ubuntu_context("below_fix"))
            fixed = scan.inspect_binary("/usr/bin/php8.3", ubuntu_context("fixed"))
            custom = scan.inspect_binary("/opt/custom/php", ubuntu_context("fixed"))
        self.assertEqual(old["status"], "below_vendor_fix")
        self.assertEqual(fixed["status"], "fixed_vendor_backport")
        self.assertEqual(custom["status"], "below_upstream_fix")

    def test_report_never_treats_fixed_cli_as_web_proof(self):
        context = ubuntu_context("fixed")
        binary = {"path": "/usr/bin/php8.3", "version": "8.3.6",
                  "status": "fixed_vendor_backport"}
        with patch.object(scan.platform, "system", return_value="Linux"), \
             patch.object(scan, "linux_context", return_value=context), \
             patch.object(scan, "candidates", return_value=["/usr/bin/php8.3"]), \
             patch.object(scan, "inspect_binary", return_value=binary):
            report = scan.make_report()
        self.assertIn("web_mapping_unverified", report["assessment"])
        self.assertEqual(report["web_evidence"]["running_php_processes"], [])

    def test_old_ubuntu_package_is_actionable(self):
        context = ubuntu_context("below_fix")
        binary = {"path": "/usr/bin/php8.3", "version": "8.3.6",
                  "status": "below_vendor_fix"}
        with patch.object(scan.platform, "system", return_value="Linux"), \
             patch.object(scan, "linux_context", return_value=context), \
             patch.object(scan, "candidates", return_value=["/usr/bin/php8.3"]), \
             patch.object(scan, "inspect_binary", return_value=binary):
            report = scan.make_report()
        self.assertEqual(report["assessment"], "ubuntu_packages_below_published_fix")
        self.assertTrue(any("8.3.6-0ubuntu0.24.04.13" in step for step in report["next_steps"]))

    def test_config_inventory_omits_unselected_secret_lines(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "site.conf"
            path.write_text("server_name example.test;\nfastcgi_param DB_PASSWORD secret-value;\n"
                            "fastcgi_pass unix:/run/php/php8.3-fpm.sock;\n", encoding="utf-8")
            with patch.object(scan.glob, "glob", side_effect=lambda pattern:
                              [str(path)] if "nginx" in pattern else []):
                result = scan.config_inventory()
        self.assertEqual(result["nginx"]["files_checked"], 1)
        self.assertNotIn("secret-value", json.dumps(result))
        self.assertEqual(len(result["nginx"]["matches"]), 1)
        self.assertNotIn("example.test", json.dumps(result))

    def test_active_route_and_short_action_plan(self):
        context = ubuntu_context("below_fix")
        context["ubuntu_security"]["packages"]["php8.3-fpm"] = {
            "installed": "8.3.6-0ubuntu0.24.04.12", "status": "below_fix"}
        context["apt_candidates"]["php8.3-fpm"] = "8.3.6-0ubuntu0.24.04.12"
        context["configuration"]["nginx"]["matches"] = [{
            "setting": "fastcgi_pass unix:/run/php/php8.3-fpm.sock;"}]
        context["configuration"]["fpm_pools"]["matches"] = [{
            "setting": "listen = /run/php/php8.3-fpm.sock"}]
        context["listeners"] = {"status": "checked", "tcp_web": [
            {"local_address": "0.0.0.0:80"}, {"local_address": "0.0.0.0:443"}],
            "php_unix": [{"socket": "/run/php/php8.3-fpm.sock"}]}
        context["process_inventory"]["entries"] = [
            {"name": "nginx", "php_module_loaded": False, "deleted_php_mapping": False},
            {"name": "php-fpm8.3", "php_module_loaded": False, "deleted_php_mapping": False}]
        binary = {"path": "/usr/bin/php8.3", "version": "8.3.6", "status": "below_vendor_fix"}
        with patch.object(scan.platform, "system", return_value="Linux"), \
             patch.object(scan, "linux_context", return_value=context), \
             patch.object(scan, "candidates", return_value=["/usr/bin/php8.3"]), \
             patch.object(scan, "inspect_binary", return_value=binary):
            report = scan.make_report()
        rendered = scan.render_report(report)
        self.assertEqual(report["web_route"]["status"], "active_local_route")
        self.assertIn("ACTION REQUIRED", rendered)
        self.assertIn("sudo apt update", rendered)
        self.assertIn("8.3.6-0ubuntu0.24.04.13", rendered)
        self.assertNotIn("{", rendered)
        self.assertNotIn("example.test", rendered)


if __name__ == "__main__":
    unittest.main()
