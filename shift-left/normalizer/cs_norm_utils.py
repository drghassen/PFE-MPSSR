"""Low-level helpers for CloudSentinelNormalizer (subprocess, paths, JSON, hashes)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class NormalizerUtilsMixin:
    def _run(self, cmd: List[str], fallback: str) -> str:
        try:
            return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
        except Exception:
            return fallback

    def _to_int(self, v: Any, fb: int) -> int:
        try:
            return int(v)
        except Exception:
            return fb

    def _sha256(self, txt: str) -> str:
        return hashlib.sha256(txt.encode("utf-8")).hexdigest()

    def _hash_file(self, p: Path) -> Optional[str]:
        if not p.is_file():
            return None
        h = hashlib.sha256()
        with p.open("rb") as f:
            for c in iter(lambda: f.read(4096), b""):
                h.update(c)
        return h.hexdigest()

    def _read_json(self, p: Path) -> Tuple[Optional[Any], Optional[str]]:
        try:
            with p.open("r", encoding="utf-8") as f:
                return json.load(f), None
        except Exception as e:
            return None, str(e)

    def _resolve_repo(self) -> str:
        ci_repo = os.environ.get("CI_PROJECT_PATH", "").strip()
        if ci_repo:
            return ci_repo
        remote = self._run(["git", "config", "--get", "remote.origin.url"], "")
        if not remote:
            return self.root.name or "unknown"
        x = re.sub(r"^https?://[^/]+/", "", remote.strip())
        x = re.sub(r"^git@[^:]+:", "", x)
        x = re.sub(r"\.git$", "", x)
        return x or self.root.name or "unknown"

    def _first(self, *vals: Any) -> Optional[str]:
        for v in vals:
            if v is not None and str(v).strip() != "":
                return str(v)
        return None

    def _norm_path(self, p: Any) -> str:
        if not p:
            return "unknown"
        s = str(p).replace("\\", "/").replace("/./", "/")
        while "//" in s:
            s = s.replace("//", "/")
        return s[2:] if s.startswith("./") else s

    def _empty_stats(self) -> Dict[str, int]:
        return {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "TOTAL": 0, "EXEMPTED": 0, "FAILED": 0, "PASSED": 0}

    def _trace_status(self, st: str, findings: List[Dict[str, Any]]) -> str:
        if st == "NOT_RUN":
            return "NOT_RUN"
        return "FAILED" if findings else "PASSED"

    def _not_run(self, tool: str, path: str, reason: str, present=False, valid=False, sha=None):
        rep = {"tool": tool, "version": "unknown", "status": "NOT_RUN", "findings": [], "errors": [reason]}
        tr = {"tool": tool, "path": path, "present": present, "valid_json": valid, "status": "NOT_RUN", "reason": reason, "sha256": sha}
        return rep, tr
