#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("cloudsentinel.normalizer")


# DB_PORTS : ports associés aux moteurs de base de données courants.
# Utilisé par correlate_intent_vs_reality() pour détecter le pattern CS-INTENT-ROLE-SPOOFING.
# DevSecOps contract : constante immuable, jamais surchargeable via env vars.
DB_PORTS: frozenset = frozenset({3306, 5432, 27017, 1433, 6379, 5984, 9042, 2181})


class CloudSentinelNormalizer:
    def __init__(self):
        self.start_time = time.time()
        self.root = Path(self._run(["git", "rev-parse", "--show-toplevel"], os.getcwd()))
        self.out_dir = self.root / ".cloudsentinel"
        self.out_file = self.out_dir / "golden_report.json"
        self.schema_version = "1.2.1"

        # Confidence map: deterministic, scanner-type-based.
        # DevSecOps contract: confidence MUST be set here, NEVER recomputed downstream.
        # Invariant: local == CI (no runtime dependency, no env var influence).
        self._confidence_map: Dict[str, str] = {
            "gitleaks": "HIGH",   # Signature-based rules — very low false positive rate
            "checkov":  "MEDIUM", # IaC heuristics — context-dependent, moderate FP risk
            "trivy":    "HIGH",   # CVE database — well-validated, very low FP rate
        }

        self.env = os.environ.get("ENVIRONMENT", os.environ.get("CI_ENVIRONMENT_NAME", "dev")).lower()
        self.env = "staging" if self.env == "stage" else self.env
        if self.env not in {"dev", "test", "staging", "prod"}:
            self.env = "dev"

        self.exec_mode = os.environ.get("CLOUDSENTINEL_EXECUTION_MODE", "ci" if "CI" in os.environ else "local").lower()
        if self.exec_mode not in {"ci", "local", "advisory"}:
            self.exec_mode = "local"
        self.local_fast = os.environ.get("CLOUDSENTINEL_LOCAL_FAST", "false").lower() == "true"
        self.schema_strict = os.environ.get("CLOUDSENTINEL_SCHEMA_STRICT", "false").lower() == "true"

        self.critical_max = 0 if os.environ.get("CI") else self._to_int(os.environ.get("CRITICAL_MAX"), 0)
        self.high_max = 2 if os.environ.get("CI") else self._to_int(os.environ.get("HIGH_MAX"), 2)

        self.ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.git_branch = (
            os.environ.get("CI_COMMIT_REF_NAME", "").strip()
            or self._run(["git", "rev-parse", "--abbrev-ref", "HEAD"], "unknown")
        )
        self.git_commit = self._run(["git", "rev-parse", "HEAD"], "unknown")
        self.git_commit_date = self._run(["git", "log", "-1", "--format=%cI"], self.ts)
        self.git_author_email = self._run(["git", "log", "-1", "--format=%ae"], "unknown@example.invalid")
        self.pipeline_id = os.environ.get("CI_PIPELINE_ID", "local")
        self.git_repo = self._resolve_repo()

        self.sev_lut = {
            "CRITICAL": "CRITICAL", "CRIT": "CRITICAL", "SEV5": "CRITICAL", "SEVERITY5": "CRITICAL", "VERY_HIGH": "CRITICAL",
            "HIGH": "HIGH", "SEV4": "HIGH", "SEVERITY4": "HIGH",
            "MEDIUM": "MEDIUM", "MODERATE": "MEDIUM", "SEV3": "MEDIUM", "SEVERITY3": "MEDIUM",
            "LOW": "LOW", "MINOR": "LOW", "SEV2": "LOW", "SEVERITY2": "LOW",
            "INFO": "INFO", "INFORMATIONAL": "INFO", "SEV1": "INFO", "SEVERITY1": "INFO", "UNKNOWN": "INFO",
        }
        self.sla = {"CRITICAL": 24, "HIGH": 168, "MEDIUM": 720, "LOW": 2160, "INFO": 8760}
        self._checkov_map: Optional[Dict[str, Dict[str, str]]] = None
        self._gitleaks_sev_map: Optional[Dict[str, str]] = None

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

    def _checkov_mapping(self) -> Dict[str, Dict[str, str]]:
        if self._checkov_map is not None:
            return self._checkov_map
        p = self.root / "shift-left" / "checkov" / "policies" / "mapping.json"
        doc, err = self._read_json(p)
        if err or not isinstance(doc, dict):
            self._checkov_map = {}
            return self._checkov_map
        out: Dict[str, Dict[str, str]] = {}
        for k, v in doc.items():
            if isinstance(v, dict):
                out[str(k)] = {"category": str(v.get("category", "UNKNOWN")), "severity": str(v.get("severity", "MEDIUM")).upper()}
        self._checkov_map = out
        return out

    def _gitleaks_mapping(self) -> Dict[str, str]:
        if self._gitleaks_sev_map is not None:
            return self._gitleaks_sev_map
        p = self.root / "shift-left" / "gitleaks" / "gitleaks.toml"
        if not p.is_file():
            self._gitleaks_sev_map = {}
            return {}
        cur: Dict[str, str] = {}
        out: Dict[str, str] = {}

        def flush():
            rid = cur.get("id", "").strip()
            if not rid:
                return
            sev = cur.get("severity", "").strip().upper()
            tags = cur.get("tags", "").lower()
            if not sev:
                sev = "CRITICAL" if "critical" in tags else "HIGH" if "high" in tags else "MEDIUM" if "medium" in tags else "LOW" if "low" in tags else "INFO" if ("info" in tags or "informational" in tags) else "HIGH"
            out[rid] = self.sev_lut.get(sev, "HIGH")

        for line in p.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith("[[rules]]"):
                flush()
                cur = {}
            elif s.startswith("id"):
                m = re.search(r'=\s*"([^"]+)"', s)
                if m:
                    cur["id"] = m.group(1)
            elif s.startswith("severity"):
                m = re.search(r'=\s*"([^"]+)"', s)
                if m:
                    cur["severity"] = m.group(1)
            elif s.startswith("tags"):
                cur["tags"] = s
        flush()
        self._gitleaks_sev_map = out
        return out

    def _parse_gitleaks(self, skip=False):
        # ENRICHISSEMENT UNIQUEMENT — gitleaks_range_raw.json n'est jamais un signal OPA.
        # La clé composite (RuleID, File, StartLine, EndLine) est la seule clé de matching.
        # Fingerprint NON utilisé : incompatible entre modes --no-git et --log-opts.
        p = self.out_dir / "gitleaks_raw.json"
        if skip:
            return self._not_run("gitleaks", str(p), "skipped_local_fast")
        if not p.is_file():
            return self._not_run("gitleaks", str(p), f"missing_report:{p}")
        sha = self._hash_file(p)
        doc, err = self._read_json(p)
        if err:
            return self._not_run("gitleaks", str(p), f"invalid_json:{p}", present=True, sha=sha)
        if not isinstance(doc, list):
            return self._not_run("gitleaks", str(p), "invalid_raw_structure:expected_array", present=True, valid=True, sha=sha)
        sev_map = self._gitleaks_mapping()
        findings: List[Dict[str, Any]] = []
        for i, it in enumerate(doc):
            if not isinstance(it, dict):
                findings.append({"id": "GITLEAKS_UNKNOWN", "description": "Malformed gitleaks finding entry", "file": "unknown", "start_line": 0, "end_line": 0, "severity": "HIGH", "status": "FAILED", "finding_type": "secret", "resource": {"name": "unknown", "path": "unknown", "type": "file"}, "metadata": {"raw_index": i, "raw_sha256": self._sha256(str(it))}})
                continue
            rid = self._first(it.get("RuleID"), it.get("rule_id"), "GITLEAKS_UNKNOWN")
            fp = self._norm_path(self._first(it.get("File"), it.get("file"), "unknown"))
            st = self._to_int(self._first(it.get("StartLine"), it.get("start_line"), it.get("line"), "0"), 0)
            en = self._to_int(self._first(it.get("EndLine"), it.get("end_line"), str(st)), st)
            secret = self._first(it.get("Secret"), it.get("Match"), it.get("match"), "") or ""
            raw_sev = self._first(it.get("Severity"), sev_map.get(str(rid), "HIGH"), "HIGH")
            findings.append({"id": rid, "description": self._first(it.get("Description"), "No description"), "file": fp, "start_line": st, "end_line": en, "severity": self.sev_lut.get(str(raw_sev).upper(), "HIGH"), "status": "FAILED", "finding_type": "secret", "resource": {"name": fp, "path": fp, "type": "file"}, "metadata": {"secret_hash": self._sha256(secret) if secret else "", "commit": self._first(it.get("Commit"), ""), "author": self._first(it.get("Email"), ""), "date": self._first(it.get("Date"), "")}})
        # Enrichissement depuis le scan range (best-effort)
        range_p = self.out_dir / "gitleaks_range_raw.json"
        if range_p.is_file():
            range_doc, range_err = self._read_json(range_p)
            if not range_err and isinstance(range_doc, list):
                # Index clé composite : (RuleID.upper(), norm_path(File), StartLine, EndLine)
                range_index: Dict[tuple, Dict[str, Any]] = {}
                for r_item in range_doc:
                    if not isinstance(r_item, dict):
                        continue
                    r_rid   = str(r_item.get("RuleID") or "").upper().strip()
                    r_file  = self._norm_path(r_item.get("File") or "")
                    r_start = self._to_int(r_item.get("StartLine"), 0)
                    r_end   = self._to_int(r_item.get("EndLine"), r_start)
                    r_commit = str(r_item.get("Commit") or "").strip()
                    r_email  = str(r_item.get("Email") or "").strip()
                    r_date   = str(r_item.get("Date") or "").strip()

                    if not r_rid or not r_file:
                        continue
                    # Valider : commit non vide + date parseable ISO8601
                    if not r_commit:
                        continue
                    try:
                        datetime.fromisoformat(r_date.replace("Z", "+00:00"))
                    except (ValueError, AttributeError):
                        continue

                    key = (r_rid, r_file, r_start, r_end)
                    if key not in range_index:
                        range_index[key] = r_item

                # Injecter les metadata dans les findings du principal
                for f in findings:
                    f_rid   = str(f.get("id") or "").upper().strip()
                    f_file  = self._norm_path(f.get("file") or "")
                    f_start = self._to_int(f.get("start_line"), 0)
                    f_end   = self._to_int(f.get("end_line"), f_start)
                    key = (f_rid, f_file, f_start, f_end)
                    match = range_index.get(key)
                    if match:
                        r_email = str(match.get("Email") or "").strip()
                        if "@" in r_email:  # email minimal valide
                            meta = f.get("metadata")
                            if isinstance(meta, dict):
                                meta["commit"] = str(match.get("Commit") or "").strip()
                                meta["author"] = r_email
                                meta["date"]   = str(match.get("Date") or "").strip()

        rep = {"tool": "gitleaks", "version": os.environ.get("GITLEAKS_VERSION", "unknown"), "status": "OK", "findings": findings, "errors": []}
        tr = {"tool": "gitleaks", "path": str(p), "present": True, "valid_json": True, "status": self._trace_status("OK", findings), "reason": "", "sha256": sha}
        return rep, tr

    def _parse_checkov(self, skip=False):
        p = self.out_dir / "checkov_raw.json"
        if skip:
            return self._not_run("checkov", str(p), "skipped_local_fast")
        if not p.is_file():
            return self._not_run("checkov", str(p), f"missing_report:{p}")
        sha = self._hash_file(p)
        doc, err = self._read_json(p)
        if err:
            return self._not_run("checkov", str(p), f"invalid_json:{p}", present=True, sha=sha)
        if not isinstance(doc, dict) or not isinstance(doc.get("results"), dict):
            return self._not_run("checkov", str(p), "invalid_raw_structure:expected_object_results", present=True, valid=True, sha=sha)
        failed = doc.get("results", {}).get("failed_checks", [])
        if not isinstance(failed, list):
            failed = []
        cmap = self._checkov_mapping()
        findings: List[Dict[str, Any]] = []
        for i, it in enumerate(failed):
            if not isinstance(it, dict):
                continue
            cid = self._first(it.get("check_id"), "CHECKOV_UNKNOWN")
            me = cmap.get(str(cid), {})
            fp = self._norm_path(self._first(it.get("file_path"), it.get("file_abs_path"), "unknown"))
            lr = it.get("file_line_range", [])
            ln = self._to_int(lr[0] if isinstance(lr, list) and lr else 0, 0)
            sev = self.sev_lut.get(str(self._first(it.get("severity"), me.get("severity"), "MEDIUM")).upper(), "MEDIUM")
            refs = []
            g = self._first(it.get("guideline"), "")
            if g:
                refs.append(g)
            findings.append({"id": cid, "description": self._first(it.get("check_name"), it.get("check_id"), "No description"), "file": fp, "line": ln, "severity": sev, "status": "FAILED", "category": self._first(me.get("category"), "INFRASTRUCTURE_AS_CODE"), "finding_type": "misconfig", "resource": {"name": self._first(it.get("resource"), fp, "unknown"), "path": fp, "type": "infrastructure"}, "references": refs, "metadata": {"raw_index": i}})
        sm = doc.get("summary", {}) if isinstance(doc.get("summary"), dict) else {}
        rep = {"tool": "checkov", "version": self._first(sm.get("checkov_version"), os.environ.get("CHECKOV_VERSION"), "unknown"), "status": "OK", "findings": findings, "errors": []}
        tr = {"tool": "checkov", "path": str(p), "present": True, "valid_json": True, "status": self._trace_status("OK", findings), "reason": "", "sha256": sha}
        return rep, tr

    def _cvss(self, v: Any) -> Optional[float]:
        if not isinstance(v, dict):
            return None
        for x in v.values():
            if isinstance(x, dict) and x.get("V3Score") is not None:
                try:
                    return float(x.get("V3Score"))
                except Exception:
                    return None
        return None

    def _trivy_from_doc(self, doc: Dict[str, Any], scan_type: str) -> List[Dict[str, Any]]:
        res = doc.get("Results", [])
        if not isinstance(res, list):
            return []
        out: List[Dict[str, Any]] = []
        for r in res:
            if not isinstance(r, dict):
                continue
            tgt = self._first(r.get("Target"), "unknown") or "unknown"
            for v in (r.get("Vulnerabilities", []) if isinstance(r.get("Vulnerabilities"), list) else []):
                if not isinstance(v, dict):
                    continue
                out.append({"id": self._first(v.get("VulnerabilityID"), "TRIVY_VULN_UNKNOWN"), "description": self._first(v.get("Title"), v.get("Description"), "No description"), "severity": self._first(v.get("Severity"), "MEDIUM"), "status": "FAILED", "finding_type": "vulnerability", "resource": {"name": self._first(v.get("PkgName"), tgt, "unknown"), "path": tgt, "type": "package", "version": self._first(v.get("InstalledVersion"), "N/A")}, "references": [str(x) for x in (v.get("References") or []) if isinstance(x, str)], "fix_version": self._first(v.get("FixedVersion"), "N/A"), "metadata": {"scan_type": scan_type, "installed_version": self._first(v.get("InstalledVersion"), ""), "fixed_version": self._first(v.get("FixedVersion"), ""), "cvss": self._cvss(v.get("CVSS"))}})
            for s in (r.get("Secrets", []) if isinstance(r.get("Secrets"), list) else []):
                if not isinstance(s, dict):
                    continue
                st = self._to_int(s.get("StartLine"), 0)
                en = self._to_int(s.get("EndLine"), st)
                material = self._first(s.get("Match"), s.get("Code"), "") or ""
                out.append({"id": self._first(s.get("RuleID"), "TRIVY_SECRET_UNKNOWN"), "description": self._first(s.get("Title"), "Secret detected"), "severity": self._first(s.get("Severity"), "HIGH"), "status": "FAILED", "finding_type": "secret", "resource": {"name": tgt, "path": tgt, "type": "asset"}, "start_line": st, "end_line": en, "references": [], "metadata": {"scan_type": scan_type, "secret_hash": self._sha256(material) if material else ""}})
            for m in (r.get("Misconfigurations", []) if isinstance(r.get("Misconfigurations"), list) else []):
                if not isinstance(m, dict):
                    continue
                st = "PASSED" if str(m.get("Status", "")).upper() == "PASS" else "FAILED"
                out.append({"id": self._first(m.get("ID"), "TRIVY_MISCONFIG_UNKNOWN"), "description": self._first(m.get("Title"), m.get("Message"), "No description"), "severity": self._first(m.get("Severity"), "MEDIUM"), "status": st, "finding_type": "misconfig", "resource": {"name": tgt, "path": self._first((m.get("CauseMetadata") or {}).get("Resource"), tgt, "unknown"), "type": "configuration"}, "references": [str(x) for x in (m.get("References") or []) if isinstance(x, str)], "metadata": {"scan_type": scan_type}})
        return out

    def _parse_trivy(self, skip=False):
        paths = {"fs": self.root / "shift-left/trivy/reports/raw/trivy-fs-raw.json", "config": self.root / "shift-left/trivy/reports/raw/trivy-config-raw.json"}
        tr_path = str(self.root / "shift-left/trivy/reports/raw")
        if skip:
            return self._not_run("trivy", tr_path, "skipped_local_fast")
        findings: List[Dict[str, Any]] = []
        errs: List[str] = []
        not_run = False
        ver = "unknown"
        present = True
        valid = True
        for st, p in paths.items():
            if not p.is_file():
                errs.append(f"missing_report:{p}")
                not_run = True
                present = False
                continue
            doc, err = self._read_json(p)
            if err:
                errs.append(f"invalid_json:{p}")
                not_run = True
                valid = False
                continue
            if not isinstance(doc, dict):
                errs.append(f"invalid_raw_structure:{p}")
                not_run = True
                valid = False
                continue
            meta = doc.get("Trivy", {})
            if isinstance(meta, dict):
                ver = self._first(meta.get("Version"), ver, "unknown") or "unknown"
            findings.extend(self._trivy_from_doc(doc, st))
        # --- Trivy image : agrégation Option A (dossier raw/image/) ---
        # TRIVY_IMAGE_MIN_REPORTS doit correspondre au nombre de jobs
        # trivy-image-scan-* dans shift-left.yml. Mettre à jour si une image est ajoutée.
        TRIVY_IMAGE_MIN_REPORTS = int(os.environ.get("TRIVY_IMAGE_MIN_REPORTS", "3"))
        image_dir = self.root / "shift-left" / "trivy" / "reports" / "raw" / "image"
        image_files = sorted(image_dir.glob("trivy-image-*-raw.json")) if image_dir.is_dir() else []

        if self.exec_mode == "ci":
            if len(image_files) < TRIVY_IMAGE_MIN_REPORTS:
                reason = f"image_reports_below_minimum:{len(image_files)}<{TRIVY_IMAGE_MIN_REPORTS}"
                errs.append(reason)
                not_run = True
            else:
                for img_p in image_files:
                    img_doc, img_err = self._read_json(img_p)
                    if img_err:
                        errs.append(f"invalid_json:{img_p}")
                        not_run = True
                        valid = False
                        continue
                    if not isinstance(img_doc, dict):
                        errs.append(f"invalid_raw_structure:{img_p}")
                        not_run = True
                        valid = False
                        continue
                    meta = img_doc.get("Trivy", {})
                    if isinstance(meta, dict):
                        ver = self._first(meta.get("Version"), ver, "unknown") or "unknown"
                    findings.extend(self._trivy_from_doc(img_doc, "image"))
        else:
            # Mode local : 0 fichiers image acceptés sans erreur
            for img_p in image_files:
                img_doc, img_err = self._read_json(img_p)
                if img_err or not isinstance(img_doc, dict):
                    continue
                meta = img_doc.get("Trivy", {})
                if isinstance(meta, dict):
                    ver = self._first(meta.get("Version"), ver, "unknown") or "unknown"
                findings.extend(self._trivy_from_doc(img_doc, "image"))

        status = "NOT_RUN" if not_run else "OK"
        rep = {"tool": "trivy", "version": ver, "status": status, "findings": findings, "errors": errs}
        tr = {"tool": "trivy", "path": tr_path, "present": present, "valid_json": valid, "status": self._trace_status(status, findings), "reason": ";".join(errs), "sha256": None}
        return rep, tr

    def _category(self, f: Dict[str, Any], tool: str) -> str:
        raw = (self._first(f.get("category"), f.get("Category"), "") or "").upper()
        st = (self._first(f.get("finding_type"), f.get("source", {}).get("scanner_type"), "") or "").lower()
        if tool == "gitleaks":
            return "SECRETS"
        if tool == "checkov":
            return "INFRASTRUCTURE_AS_CODE"
        if raw in {"SECRET", "SECRETS"} or st == "secret":
            return "SECRETS"
        return "VULNERABILITIES"

    def _fingerprint(self, tool: str, rid: str, rname: str, rpath: str, sl: int, el: int, secret_hash: str) -> str:
        ctx = "|".join([rpath.lower(), str(sl), str(el), secret_hash.strip().lower()])
        return hashlib.sha256("|".join([tool.lower(), rid.strip().upper(), rname.lower(), ctx]).encode("utf-8")).hexdigest()

    def _normalize_finding(self, f: Dict[str, Any], tool: str, version: str, idx: int) -> Dict[str, Any]:
        rid = self._first(f.get("id"), f.get("rule_id"), f.get("RuleID"), f.get("VulnerabilityID"), "UNKNOWN")
        desc = self._first(f.get("description"), f.get("message"), f.get("title"), f.get("check_name"), "No description")
        cat = self._category(f, tool)
        rsrc = f.get("resource", {}) if isinstance(f.get("resource"), dict) else {}
        rname = self._first(rsrc.get("name"), f.get("resource") if isinstance(f.get("resource"), str) else None, f.get("file"), f.get("target"), "unknown")
        rpath = self._norm_path(self._first(rsrc.get("path"), f.get("file"), f.get("target"), "unknown"))
        meta = f.get("metadata", {}) if isinstance(f.get("metadata"), dict) else {}
        loc = rsrc.get("location", {}) if isinstance(rsrc.get("location"), dict) else {}
        sl = self._to_int(loc.get("start_line") or f.get("start_line") or f.get("line") or meta.get("line"), 0)
        el = self._to_int(loc.get("end_line") or f.get("end_line") or meta.get("end_line"), sl)
        sd = f.get("severity", {}) if isinstance(f.get("severity"), dict) else {}
        raw_sev = f.get("severity") if isinstance(f.get("severity"), str) else (sd.get("level") or f.get("original_severity"))
        sev = self.sev_lut.get(str(raw_sev).upper(), "MEDIUM")
        # Status normalization: set once at normalization, immutable downstream.
        # DevSecOps rule: only PASSED (scanner explicit pass, e.g. Trivy misconfig)
        # or FAILED (all detections). EXEMPTED is NOT a valid raw-input status —
        # duplicate tracking lives exclusively in context.deduplication metadata.
        raw_st = str(f.get("status", "FAILED")).upper()
        st = "PASSED" if raw_st == "PASSED" else "FAILED"
        secret_hash = str(meta.get("secret_hash", "")).strip()
        fp = self._fingerprint(tool, str(rid), str(rname), rpath, sl, el, secret_hash)
        fid = f"CS-{tool}-{hashlib.sha256(f'{fp}|{idx}'.encode('utf-8')).hexdigest()[:16]}"
        cvss = sd.get("cvss_score") or f.get("cvss_score") or meta.get("cvss")
        try:
            cvss = float(cvss) if cvss is not None else None
        except Exception:
            cvss = None
        refs = f.get("references") or meta.get("references") or []
        refs = refs if isinstance(refs, list) else []
        # --- Confidence: set once at normalization, never recomputed ---
        # Mapping is deterministic (scanner → confidence level).
        # DevSecOps invariant: confidence is stable between local and CI execution.
        confidence = self._confidence_map.get(tool.lower(), "MEDIUM")
        return {
            "id": fid,
            "confidence": confidence,
            "source": {"tool": tool, "version": version or "unknown", "id": str(rid), "scanner_type": self._first(f.get("finding_type"), f.get("source", {}).get("scanner_type"), cat.lower(), "security")},
            "resource": {"name": rname, "version": self._first(rsrc.get("version"), meta.get("installed_version"), "N/A"), "type": self._first(rsrc.get("type"), f.get("finding_type"), "asset"), "path": rpath, "location": {"file": rpath, "start_line": sl, "end_line": el}},
            "description": str(desc),
            "severity": {"level": sev, "original_severity": self._first(sd.get("level"), raw_sev, "UNKNOWN"), "cvss_score": cvss},
            "category": cat,
            "status": st,
            "remediation": {"sla_hours": self.sla.get(sev, 720), "fix_version": self._first(f.get("fix_version"), meta.get("fixed_version"), "N/A"), "references": [str(x) for x in refs]},
            "context": {"git": {"author_email": self.git_author_email, "commit_date": self.git_commit_date}, "deduplication": {"fingerprint": fp, "is_duplicate": False, "duplicate_of": None}, "traceability": {"source_report": f"{tool}_raw.json", "source_index": idx, "normalized_at": self.ts}},
        }

    def _process_scanner(self, data: Dict[str, Any], name: str) -> Dict[str, Any]:
        v = str(data.get("version", "unknown"))
        st = "NOT_RUN" if str(data.get("status", "NOT_RUN")).upper() == "NOT_RUN" else "OK"
        raws = data.get("findings", [])
        raws = raws if isinstance(raws, list) else []
        return {"tool": name, "version": v, "status": st, "errors": [str(x) for x in data.get("errors", [])], "stats": self._empty_stats(), "findings": [self._normalize_finding(f, name, v, i) for i, f in enumerate(raws)]}

    def _dedup(self, findings: List[Dict[str, Any]]) -> None:
        """Metadata enrichment pass — marks duplicate findings via context.deduplication.

        DevSecOps contract (non-negotiable):
          - ONLY modifies: context.deduplication.is_duplicate
          - ONLY modifies: context.deduplication.duplicate_of
          - NEVER modifies: status, severity, confidence, category
          - Deduplication = metadata enrichment, NOT state mutation.

        Duplicate signal consumers:
          - OPA: reads `context.deduplication.is_duplicate` (not status) to exclude dupes
          - _stats(): reads `context.deduplication.is_duplicate` for EXEMPTED counter
        """
        seen: Dict[str, str] = {}
        for f in findings:
            d = f.get("context", {}).get("deduplication", {})
            fp = str(d.get("fingerprint", "")).strip()
            if not fp:
                continue
            if fp in seen:
                d["is_duplicate"] = True
                d["duplicate_of"] = seen[fp]
                # status intentionally NOT modified — immutable after normalization.
            else:
                seen[fp] = f.get("id")
                d["is_duplicate"] = False
                d["duplicate_of"] = None

    def _stats(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        s = self._empty_stats()
        for f in findings:
            # Deduplication signal: read from metadata, NOT from status.
            # status is immutable after _normalize_finding(); _dedup() only enriches metadata.
            is_dup = bool(f.get("context", {}).get("deduplication", {}).get("is_duplicate", False))
            if is_dup:
                s["EXEMPTED"] += 1
                continue
            st = str(f.get("status", "FAILED")).upper()
            if st == "PASSED":
                s["PASSED"] += 1
                continue
            if st != "FAILED":
                continue
            s["FAILED"] += 1
            s["TOTAL"] += 1
            sev = str(f.get("severity", {}).get("level", "MEDIUM")).upper()
            s[sev if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else "MEDIUM"] += 1
        return s

    def extract_intent_contract(self, terraform_plan_path: str) -> Dict[str, Any]:
        """Extrait le contrat d'intention depuis un fichier JSON issu de `terraform show -json`.

        Cherche la clé ``variables.resource_intent.value`` dans le plan Terraform.

        Retourne :
          - ``{"declared": <dict resource_intent>, "violation": None}`` si le contrat est présent
            et valide.
          - ``{"declared": None, "violation": "MISSING_INTENT_CONTRACT"}`` si le fichier est absent,
            non lisible, ou ne contient pas la clé ``resource_intent``. Ce cas déclenche
            ``CS-INTENT-CONTRACT-MISSING`` dans OPA (deny CRITICAL, non_waivable).

        Args:
            terraform_plan_path: Chemin vers le fichier JSON produit par
                ``terraform show -json <planfile>``.
        """
        logger.info("[intent] Lecture contrat : %s", terraform_plan_path)
        p = Path(terraform_plan_path)
        _missing: Dict[str, Any] = {"declared": None, "violation": "MISSING_INTENT_CONTRACT"}

        if not p.is_file():
            logger.error("[intent] \u274c tfplan.json introuvable : %s", terraform_plan_path)
            return _missing

        try:
            with p.open("r", encoding="utf-8") as f:
                doc = json.load(f)
        except Exception as e:
            logger.error("[intent] \u274c JSON invalide : %s", e)
            return _missing

        if not isinstance(doc, dict):
            logger.error("[intent] \u274c resource_intent absent du plan Terraform")
            return _missing

        variables = doc.get("variables")
        if not isinstance(variables, dict):
            logger.error("[intent] \u274c resource_intent absent du plan Terraform")
            return _missing

        intent_raw = variables.get("resource_intent")
        if not isinstance(intent_raw, dict):
            logger.error("[intent] \u274c resource_intent absent du plan Terraform")
            return _missing

        # `terraform show -json` encapsule la valeur dans {"value": {...}}
        value = intent_raw.get("value")
        if not isinstance(value, dict):
            logger.error("[intent] \u274c resource_intent absent du plan Terraform")
            return _missing

        required_keys = {"service_type", "exposure_level", "owner", "approved_by"}
        if not required_keys.issubset(value.keys()):
            logger.error("[intent] \u274c resource_intent absent du plan Terraform")
            return _missing

        declared = {
            "service_type":   str(value.get("service_type", "")),
            "exposure_level": str(value.get("exposure_level", "")),
            "owner":          str(value.get("owner", "")),
            "approved_by":    str(value.get("approved_by", "")),
        }
        logger.info(
            "[intent] \u2705 Contrat extrait \u2014 service_type=%s exposure=%s",
            declared["service_type"],
            declared["exposure_level"],
        )
        return {"declared": declared, "violation": None}

    def correlate_intent_vs_reality(self, intent: Dict[str, Any], findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Corrèle le contrat d'intention déclaré avec les findings normalisés des scanners.

        Détecte deux patterns de role spoofing :

        **Pattern 1 — CS-INTENT-ROLE-SPOOFING** (MITRE T1036 - Masquerading) :
          Une ressource déclarée ``web-server`` présente des ports de base de données
          dans les findings. Indique qu'une DB est déployée sous couvert d'un serveur web.

        **Pattern 2 — CS-INTENT-EXPOSURE-MISMATCH** (MITRE T1048 - Exfiltration Over Alternative Protocol) :
          Une ressource déclarée ``internal-only`` présente une IP publique ou une règle
          ``0.0.0.0/0`` dans les findings. Indique une exposition Internet non déclarée.

        Args:
            intent: Résultat de ``extract_intent_contract()`` (champ ``declared`` requis).
            findings: Liste des findings normalisés du Golden Report (post-``_dedup``).

        Returns:
            Liste d'objets ``intent_mismatch``. Vide si aucun écart n'est détecté.
        """
        logger.info("[correlate] Corrélation sur %d findings...", len(findings))
        declared = intent.get("declared") if isinstance(intent, dict) else None
        if not isinstance(declared, dict):
            return []

        service_type = str(declared.get("service_type", "")).strip().lower()
        exposure_level = str(declared.get("exposure_level", "")).strip().lower()
        mismatches: List[Dict[str, Any]] = []

        # Pré-calcul des champs textuels utiles pour la détection, une seule passe.
        def _finding_text(f: Dict[str, Any]) -> str:
            return " ".join([
                str(f.get("description", "")),
                str((f.get("source") or {}).get("id", "")),
                str((f.get("resource") or {}).get("name", "")),
                str((f.get("resource") or {}).get("path", "")),
            ])

        def _finding_fingerprint(f: Dict[str, Any]) -> str:
            return str((f.get("context") or {}).get("deduplication", {}).get("fingerprint", f.get("id", "")))

        # ── Pattern 1 : CS-INTENT-ROLE-SPOOFING ──────────────────────────────
        if service_type == "web-server":
            db_port_findings: List[Dict[str, Any]] = []
            detected_ports: set = set()

            for f in findings:
                if str(f.get("status", "FAILED")).upper() != "FAILED":
                    continue
                text = _finding_text(f)
                for m in re.finditer(r"\b(\d{2,5})\b", text):
                    port = int(m.group(1))
                    if port in DB_PORTS:
                        db_port_findings.append(f)
                        detected_ports.add(port)
                        break  # un port DB suffit pour qualifier ce finding

            if db_port_findings:
                _observed = f"db_ports_detected={{{', '.join(str(p) for p in sorted(detected_ports))}}}"
                logger.warning(
                    "[correlate] \u26a0\ufe0f  %s \u2014 déclaré: '%s' observé: '%s' MITRE: %s",
                    "CS-INTENT-ROLE-SPOOFING",
                    "service_type=web-server",
                    _observed,
                    "T1036 - Masquerading",
                )
                mismatches.append({
                    "rule":     "CS-INTENT-ROLE-SPOOFING",
                    "severity": "CRITICAL",
                    "declared": "service_type=web-server",
                    "observed": _observed,
                    "mitre":    "T1036 - Masquerading",
                    "source_findings": [_finding_fingerprint(f) for f in db_port_findings],
                })

        # ── Pattern 2 : CS-INTENT-EXPOSURE-MISMATCH ─────────────────────────
        if exposure_level == "internal-only":
            _PUBLIC_SIGNALS = re.compile(
                r"public[_\s]?ip|0\.0\.0\.0/0|0\.0\.0\.0",
                re.IGNORECASE,
            )
            exposure_findings: List[Dict[str, Any]] = []

            for f in findings:
                if str(f.get("status", "FAILED")).upper() != "FAILED":
                    continue
                text = _finding_text(f)
                if _PUBLIC_SIGNALS.search(text):
                    exposure_findings.append(f)

            if exposure_findings:
                logger.warning(
                    "[correlate] \u26a0\ufe0f  %s \u2014 déclaré: '%s' observé: '%s' MITRE: %s",
                    "CS-INTENT-EXPOSURE-MISMATCH",
                    "exposure_level=internal-only",
                    "public_ip_or_open_cidr_detected",
                    "T1048 - Exfiltration Over Alternative Protocol",
                )
                mismatches.append({
                    "rule":     "CS-INTENT-EXPOSURE-MISMATCH",
                    "severity": "HIGH",
                    "declared": "exposure_level=internal-only",
                    "observed": "public_ip_or_open_cidr_detected",
                    "mitre":    "T1048 - Exfiltration Over Alternative Protocol",
                    "source_findings": [_finding_fingerprint(f) for f in exposure_findings],
                })

        if mismatches:
            logger.info("[correlate] %d mismatch(es) détecté(s)", len(mismatches))
        else:
            logger.info("[correlate] \u2705 Aucun mismatch")
        return mismatches

    def generate(self):
        print("\033[34m[INFO]\033[0m Starting CloudSentinel normalization (raw ingestion)...")
        skip = self.local_fast and self.exec_mode in {"local", "advisory"}
        g_data, g_trace = self._parse_gitleaks(skip=False)
        c_data, c_trace = self._parse_checkov(skip=skip)
        t_data, t_trace = self._parse_trivy(skip=skip)

        scanners = {"gitleaks": self._process_scanner(g_data, "gitleaks"), "checkov": self._process_scanner(c_data, "checkov"), "trivy": self._process_scanner(t_data, "trivy")}
        findings = scanners["gitleaks"]["findings"] + scanners["checkov"]["findings"] + scanners["trivy"]["findings"]
        self._dedup(findings)

        # ── Intent Contract : extraction + corrélation ──────────────────────
        # Le chemin du plan Terraform est configurable via TERRAFORM_PLAN_JSON.
        # Par défaut : infra/azure/student-secure/tfplan.json (produit par terraform show -json).
        # Si le fichier est absent : violation MISSING_INTENT_CONTRACT → deny OPA CRITICAL non_waivable.
        terraform_plan_path = os.environ.get(
            "TERRAFORM_PLAN_JSON",
            str(self.root / "infra" / "azure" / "student-secure" / "tfplan.json"),
        )
        intent_contract = self.extract_intent_contract(terraform_plan_path)
        intent_mismatches = self.correlate_intent_vs_reality(intent_contract, findings)
        for nm, sc in scanners.items():
            sc["stats"] = self._stats(sc["findings"])
            src = {"gitleaks": g_data, "checkov": c_data, "trivy": t_data}[nm]
            if str(src.get("status", "OK")).upper() == "NOT_RUN":
                sc["status"] = "NOT_RUN"
            elif sc["stats"]["TOTAL"] > 0:
                sc["status"] = "FAILED"
            else:
                sc["status"] = "PASSED"

        by_cat = {"SECRETS": 0, "INFRASTRUCTURE_AS_CODE": 0, "VULNERABILITIES": 0}
        for f in findings:
            if str(f.get("status", "FAILED")).upper() == "FAILED":
                c = str(f.get("category", "VULNERABILITIES"))
                if c in by_cat:
                    by_cat[c] += 1
        summary = {"global": self._stats(findings), "by_tool": {k: {**v["stats"], "status": v["status"]} for k, v in scanners.items()}, "by_category": by_cat}
        not_run = [k for k, v in scanners.items() if v["status"] == "NOT_RUN"]

        report = {
            "schema_version": self.schema_version,
            "metadata": {
                "tool": "cloudsentinel",
                "timestamp": self.ts,
                "generation_duration_ms": 0,
                "environment": self.env,
                "execution": {"mode": self.exec_mode},
                "git": {"repo": self.git_repo, "repository": self.git_repo, "branch": self.git_branch, "commit": self.git_commit, "commit_date": self.git_commit_date, "author_email": self.git_author_email, "pipeline_id": self.pipeline_id},
                "normalizer": {"version": self.schema_version, "compatibility": "backward", "source_reports": {"gitleaks": g_trace, "checkov": c_trace, "trivy": t_trace}},
            },
            "scanners": scanners,
            "findings": findings,
            "summary": summary,
            "quality_gate": {"decision": "NOT_EVALUATED", "reason": "evaluation-performed-by-opa-only", "thresholds": {"critical_max": self.critical_max, "high_max": self.high_max}, "details": {"reasons": ["opa_is_single_enforcement_point"], "not_run_scanners": not_run}},
            "intent_contract":   intent_contract,
            "intent_mismatches": intent_mismatches,
        }
        report["metadata"]["generation_duration_ms"] = int((time.time() - self.start_time) * 1000)

        self.out_dir.mkdir(parents=True, exist_ok=True)
        with self.out_file.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        self._validate_schema(report)
        print(f"\033[34m[INFO]\033[0m Golden Report generated successfully: {self.out_file}")

    def _validate_schema(self, report: Dict[str, Any]):
        schema_path = self.root / "shift-left" / "normalizer" / "schema" / "cloudsentinel_report.schema.json"
        try:
            from jsonschema import Draft7Validator, validate
            if schema_path.is_file():
                with schema_path.open("r", encoding="utf-8") as f:
                    schema = json.load(f)
                Draft7Validator.check_schema(schema)
                validate(report, schema)
        except ImportError:
            if self.schema_strict:
                print("\033[31m[ERROR]\033[0m jsonschema module missing in strict mode", file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"\033[31m[ERROR]\033[0m Golden report schema validation failed: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    import argparse

    _parser = argparse.ArgumentParser(description="CloudSentinel — Golden Report normalizer")
    _parser.add_argument(
        "--tfplan",
        default=None,
        help="Chemin vers le plan Terraform JSON (terraform show -json). "
             "Surcharge la variable d'environnement TERRAFORM_PLAN_JSON.",
    )
    _args, _ = _parser.parse_known_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s %(message)s",
        stream=sys.stderr,
    )

    if _args.tfplan:
        os.environ["TERRAFORM_PLAN_JSON"] = _args.tfplan

    CloudSentinelNormalizer().generate()
