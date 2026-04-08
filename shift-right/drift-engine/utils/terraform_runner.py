from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class TerraformCommandResult:
    cmd: list[str]
    return_code: int
    stdout: str
    stderr: str
    duration_ms: int


class TerraformRunner:
    """
    Runs Terraform commands for drift detection.

    The core drift detection uses:
      terraform plan -refresh-only -detailed-exitcode -out=<planfile>
      terraform show -json <planfile>
    """

    def __init__(
        self,
        working_dir: Path,
        env: Mapping[str, str] | None = None,
        terraform_bin: str = "terraform",
        timeout_s: int | None = None,
    ) -> None:
        self.working_dir = working_dir
        self.terraform_bin = terraform_bin

        # Priority: explicit arg > TF_PLAN_TIMEOUT_S env var > default 600s
        if timeout_s is not None:
            self.timeout_s = timeout_s
        else:
            _env_val = os.getenv("TF_PLAN_TIMEOUT_S", "").strip()
            self.timeout_s = int(_env_val) if _env_val.isdigit() else 600

        merged_env = dict(os.environ)
        if env:
            merged_env.update({k: v for k, v in env.items() if v is not None})
        self.env = merged_env

    def _run(self, args: Sequence[str]) -> TerraformCommandResult:
        cmd = [self.terraform_bin, *args]
        started = time.time()
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self.working_dir),
                env=self.env,
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
                check=False,
            )
        except FileNotFoundError as exc:
            duration_ms = int((time.time() - started) * 1000)
            return TerraformCommandResult(
                cmd=cmd,
                return_code=127,
                stdout="",
                stderr=f"Terraform binary not found: {exc}",
                duration_ms=duration_ms,
            )
        except subprocess.TimeoutExpired as exc:
            duration_ms = int((time.time() - started) * 1000)
            stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
            stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", "replace")
            return TerraformCommandResult(
                cmd=cmd,
                return_code=124,
                stdout=stdout,
                stderr=f"Terraform command timed out after {self.timeout_s}s. {stderr}".strip(),
                duration_ms=duration_ms,
            )

        duration_ms = int((time.time() - started) * 1000)
        return TerraformCommandResult(
            cmd=cmd,
            return_code=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            duration_ms=duration_ms,
        )

    def version(self) -> str | None:
        result = self._run(["version", "-json"])
        if result.return_code != 0:
            return None
        try:
            payload = json.loads(result.stdout)
            return str(payload.get("terraform_version") or "")
        except Exception:
            return None

    def init(self, upgrade: bool = False, reconfigure: bool = False, backend: bool = True) -> TerraformCommandResult:
        base_args = ["init", "-input=false", "-no-color"]
        if upgrade:
            base_args.append("-upgrade")
        if reconfigure:
            base_args.append("-reconfigure")
        if not backend:
            base_args.append("-backend=false")

        # `.terraform.lock.hcl` lives in the Terraform working directory. When the IaC folder is mounted
        # read-only (recommended for drift detection), `terraform init` must not try to update the lockfile.
        # Users can override via `TF_LOCKFILE_MODE` (Terraform supports only "readonly" in newer versions).
        explicit_lockfile_mode = (self.env.get("TF_LOCKFILE_MODE") or "").strip().lower()

        lockfile_mode = explicit_lockfile_mode
        if not lockfile_mode:
            try:
                working_dir_writable = os.access(str(self.working_dir), os.W_OK)
                if not working_dir_writable:
                    lockfile_mode = "readonly"
            except Exception:
                lockfile_mode = ""

        # Optional backend configuration for cases where `backend "azurerm" {}` is empty in code.
        # Prefer simple env vars; also allow a JSON map for flexibility.
        backend_kv: dict[str, str] = {}

        def add(k: str, v: str | None) -> None:
            if v is None:
                return
            v = v.strip()
            if v:
                backend_kv[k] = v

        add("resource_group_name", self.env.get("TF_BACKEND_RESOURCE_GROUP_NAME") or self.env.get("TF_BACKEND_RG"))
        add("storage_account_name", self.env.get("TF_BACKEND_STORAGE_ACCOUNT_NAME") or self.env.get("TF_BACKEND_SA"))
        add("container_name", self.env.get("TF_BACKEND_CONTAINER_NAME") or self.env.get("TF_BACKEND_CONTAINER"))
        add("key", self.env.get("TF_BACKEND_KEY"))
        add("use_azuread_auth", self.env.get("TF_BACKEND_USE_AZUREAD_AUTH"))

        backend_config_json = self.env.get("TF_BACKEND_CONFIG_JSON")
        if backend_config_json:
            try:
                cfg = json.loads(backend_config_json)
                if isinstance(cfg, dict):
                    for k, v in cfg.items():
                        if isinstance(k, str) and isinstance(v, str) and v.strip():
                            backend_kv.setdefault(k, v.strip())
            except Exception:
                pass

        for k in sorted(backend_kv.keys()):
            base_args.append(f"-backend-config={k}={backend_kv[k]}")

        def run_with_lockfile(mode: str | None) -> TerraformCommandResult:
            args = list(base_args)
            if mode == "readonly":
                args.append("-lockfile=readonly")
            return self._run(args)

        if explicit_lockfile_mode == "readonly":
            return run_with_lockfile("readonly")
        if explicit_lockfile_mode:
            # Unknown/unsupported mode for this Terraform version -> fall back to default.
            return self._run(base_args)

        if lockfile_mode == "readonly":
            return run_with_lockfile("readonly")

        return self._run(base_args)

    def workspace_select_or_create(self, workspace: str) -> TerraformCommandResult:
        if not workspace or workspace == "default":
            return TerraformCommandResult(
                cmd=[self.terraform_bin, "workspace", "select", "default"],
                return_code=0,
                stdout="",
                stderr="",
                duration_ms=0,
            )
        select = self._run(["workspace", "select", "-no-color", workspace])
        if select.return_code == 0:
            return select
        return self._run(["workspace", "new", "-no-color", workspace])

    def plan_refresh_only(
        self,
        plan_path: Path,
        lock_timeout: str = "60s",
        parallelism: int = 10,
    ) -> TerraformCommandResult:
        plan_path.parent.mkdir(parents=True, exist_ok=True)
        args = [
            "plan",
            "-refresh-only",
            "-detailed-exitcode",
            "-input=false",
            "-no-color",
            f"-lock-timeout={lock_timeout}",
            f"-parallelism={parallelism}",
            f"-out={str(plan_path)}",
        ]
        return self._run(args)

    def show_plan_json(self, plan_path: Path) -> dict[str, Any] | None:
        result = self._run(["show", "-json", str(plan_path)])
        if result.return_code != 0:
            return None
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def redact_cmd(cmd: Sequence[str]) -> str:
        return " ".join(shlex.quote(a) for a in cmd)
