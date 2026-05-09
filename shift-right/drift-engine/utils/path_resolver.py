from __future__ import annotations

import os
import shutil
from pathlib import Path


def resolve_engine_root(config_path: Path) -> Path:
    """Derive the drift-engine root from the config file path."""
    resolved = config_path.resolve()
    if resolved.name != "drift_config.yaml":
        # utils/path_resolver.py → utils/ → drift-engine/
        return Path(__file__).resolve().parent.parent
    # drift-engine/config/drift_config.yaml → drift-engine/
    return resolved.parent.parent


def resolve_path_under(root: Path, value: str) -> Path:
    """Resolve a config path (template/output) relative to the engine root."""
    p = Path(value).expanduser()
    return p if p.is_absolute() else (root / p).resolve()


def choose_tf_binary(tf_working_dir: Path) -> str:
    """
    Select the IaC CLI binary:
    1. TF_BINARY / TF_BIN env var takes precedence.
    2. If the lockfile references OpenTofu and `tofu` is on PATH, use `tofu`.
    3. Fall back to `terraform`.
    """
    explicit = (os.getenv("TF_BINARY") or os.getenv("TF_BIN") or "").strip()
    if explicit:
        return explicit

    lockfile_path = tf_working_dir / ".terraform.lock.hcl"
    if lockfile_path.exists():
        try:
            content = lockfile_path.read_text(encoding="utf-8", errors="ignore")
            if (
                "registry.opentofu.org" in content or "opentofu" in content
            ) and shutil.which("tofu"):
                return "tofu"
        except Exception:
            pass

    return "terraform"
