"""Raw scanner report ingestion (Gitleaks, Checkov, Trivy)."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List, Optional


class NormalizerRawParsersMixin:
    def _gitleaks_secret_hash(
        self,
        item: Dict[str, Any],
        rule_id: str,
        file_path: str,
        start_line: int,
        end_line: int,
    ) -> str:
        precomputed = self._first(
            item.get("CloudSentinelSecretHash"),
            item.get("SecretHash"),
            item.get("secret_hash"),
            "",
        )
        if precomputed and len(str(precomputed).strip()) == 64:
            return str(precomputed).strip().lower()

        secret = (
            self._first(item.get("Secret"), item.get("secret"), item.get("Match"), item.get("match"), "")
            or ""
        )
        if secret and str(secret).strip().upper() != "REDACTED":
            return self._sha256(str(secret))

        st_col = self._to_int(
            self._first(item.get("StartColumn"), item.get("start_column"), "0"), 0
        )
        en_col = self._to_int(
            self._first(item.get("EndColumn"), item.get("end_column"), "0"), 0
        )
        fallback_material = "|".join(
            [
                "v1",
                "location",
                str(rule_id).upper(),
                self._norm_path(file_path),
                str(start_line),
                str(end_line),
                str(st_col),
                str(en_col),
            ]
        )
        return self._sha256(fallback_material)

    def _parse_gitleaks(self, skip=False):
        # ENRICHISSEMENT UNIQUEMENT — gitleaks_range_raw.json n'est jamais un signal OPA.
        # La clé composite (RuleID, File, StartLine, EndLine, SecretHash) est la seule clé de matching.
        # Fingerprint NON utilisé : incompatible entre modes --no-git et --log-opts.
        p = self.out_dir / "gitleaks_raw.json"
        if skip:
            return self._not_run("gitleaks", str(p), "skipped_local_fast")
        if not p.is_file():
            return self._not_run("gitleaks", str(p), f"missing_report:{p}")
        sha = self._hash_file(p)
        doc, err = self._read_json(p)
        if err:
            return self._not_run(
                "gitleaks", str(p), f"invalid_json:{p}", present=True, sha=sha
            )
        if not isinstance(doc, list):
            return self._not_run(
                "gitleaks",
                str(p),
                "invalid_raw_structure:expected_array",
                present=True,
                valid=True,
                sha=sha,
            )
        sev_map = self._gitleaks_mapping()
        findings: List[Dict[str, Any]] = []
        for i, it in enumerate(doc):
            if not isinstance(it, dict):
                findings.append(
                    {
                        "id": "GITLEAKS_UNKNOWN",
                        "description": "Malformed gitleaks finding entry",
                        "file": "unknown",
                        "start_line": 0,
                        "end_line": 0,
                        "severity": "HIGH",
                        "status": "FAILED",
                        "finding_type": "secret",
                        "resource": {
                            "name": "unknown",
                            "path": "unknown",
                            "type": "file",
                        },
                        "metadata": {
                            "raw_index": i,
                            "raw_sha256": self._sha256(str(it)),
                        },
                    }
                )
                continue
            rid = self._first(it.get("RuleID"), it.get("rule_id"), "GITLEAKS_UNKNOWN")
            fp = self._norm_path(self._first(it.get("File"), it.get("file"), "unknown"))
            st = self._to_int(
                self._first(
                    it.get("StartLine"), it.get("start_line"), it.get("line"), "0"
                ),
                0,
            )
            en = self._to_int(
                self._first(it.get("EndLine"), it.get("end_line"), str(st)), st
            )
            secret_hash = self._gitleaks_secret_hash(it, str(rid), fp, st, en)
            raw_sev = self._first(
                it.get("Severity"), sev_map.get(str(rid), "HIGH"), "HIGH"
            )
            findings.append(
                {
                    "id": rid,
                    "description": self._first(it.get("Description"), "No description"),
                    "file": fp,
                    "start_line": st,
                    "end_line": en,
                    "severity": self.sev_lut.get(str(raw_sev).upper(), "HIGH"),
                    "status": "FAILED",
                    "finding_type": "secret",
                    "resource": {"name": fp, "path": fp, "type": "file"},
                    "metadata": {
                        "secret_hash": secret_hash,
                        "commit": self._first(it.get("Commit"), ""),
                        "author": self._first(it.get("Email"), ""),
                        "date": self._first(it.get("Date"), ""),
                    },
                }
            )
        # Enrichissement depuis le scan range (best-effort)
        # Si le range file est absent, in_latest_push = True par défaut (conservatif — on bloque)
        range_p = self.out_dir / "gitleaks_range_raw.json"
        if not range_p.is_file():
            for f in findings:
                meta = f.get("metadata")
                if isinstance(meta, dict):
                    meta.setdefault("in_latest_push", True)
        if range_p.is_file():
            range_doc, range_err = self._read_json(range_p)
            if not range_err and isinstance(range_doc, list):
                # Index clé composite : (RuleID.upper(), norm_path(File), StartLine, EndLine, SecretHash)
                range_index: Dict[tuple, Dict[str, Any]] = {}
                for r_item in range_doc:
                    if not isinstance(r_item, dict):
                        continue
                    r_rid = str(r_item.get("RuleID") or "").upper().strip()
                    r_file = self._norm_path(r_item.get("File") or "")
                    r_start = self._to_int(r_item.get("StartLine"), 0)
                    r_end = self._to_int(r_item.get("EndLine"), r_start)
                    r_hash = self._gitleaks_secret_hash(
                        r_item, r_rid, r_file, r_start, r_end
                    )
                    r_commit = str(r_item.get("Commit") or "").strip()
                    r_email = str(r_item.get("Email") or "").strip()
                    r_date = str(r_item.get("Date") or "").strip()

                    if not r_rid or not r_file:
                        continue
                    # Valider : commit non vide + date parseable ISO8601
                    if not r_commit:
                        continue
                    try:
                        datetime.fromisoformat(r_date.replace("Z", "+00:00"))
                    except (ValueError, AttributeError):
                        continue

                    key = (r_rid, r_file, r_start, r_end, r_hash)
                    if key not in range_index:
                        range_index[key] = r_item

                # Injecter les metadata + marquer in_latest_push dans les findings du principal
                for f in findings:
                    f_rid = str(f.get("id") or "").upper().strip()
                    f_file = self._norm_path(f.get("file") or "")
                    f_start = self._to_int(f.get("start_line"), 0)
                    f_end = self._to_int(f.get("end_line"), f_start)
                    meta = f.get("metadata")
                    f_hash = ""
                    if isinstance(meta, dict):
                        f_hash = str(meta.get("secret_hash") or "").strip().lower()
                    key = (f_rid, f_file, f_start, f_end, f_hash)
                    if isinstance(meta, dict):
                        # True = finding introduced in the current push → pipeline blocks on it
                        # False = historical finding from prior commits → advisory only, never blocks
                        meta["in_latest_push"] = key in range_index
                    match = range_index.get(key)
                    if match:
                        r_email = str(match.get("Email") or "").strip()
                        if "@" in r_email:  # email minimal valide
                            if isinstance(meta, dict):
                                meta["commit"] = str(match.get("Commit") or "").strip()
                                meta["author"] = r_email
                                meta["date"] = str(match.get("Date") or "").strip()

        rep = {
            "tool": "gitleaks",
            "version": os.environ.get("GITLEAKS_VERSION", "unknown"),
            "status": "OK",
            "findings": findings,
            "errors": [],
        }
        tr = {
            "tool": "gitleaks",
            "path": str(p),
            "present": True,
            "valid_json": True,
            "status": self._trace_status("OK", findings),
            "reason": "",
            "sha256": sha,
        }
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
            return self._not_run(
                "checkov", str(p), f"invalid_json:{p}", present=True, sha=sha
            )
        if not isinstance(doc, dict) or not isinstance(doc.get("results"), dict):
            return self._not_run(
                "checkov",
                str(p),
                "invalid_raw_structure:expected_object_results",
                present=True,
                valid=True,
                sha=sha,
            )
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
            fp = self._norm_path(
                self._first(it.get("file_path"), it.get("file_abs_path"), "unknown")
            )
            lr = it.get("file_line_range", [])
            ln = self._to_int(lr[0] if isinstance(lr, list) and lr else 0, 0)
            sev = self.sev_lut.get(
                str(
                    self._first(it.get("severity"), me.get("severity"), "MEDIUM")
                ).upper(),
                "MEDIUM",
            )
            refs = []
            g = self._first(it.get("guideline"), "")
            if g:
                refs.append(g)
            findings.append(
                {
                    "id": cid,
                    "description": self._first(
                        it.get("check_name"), it.get("check_id"), "No description"
                    ),
                    "file": fp,
                    "line": ln,
                    "severity": sev,
                    "status": "FAILED",
                    "category": self._first(
                        me.get("category"), "INFRASTRUCTURE_AS_CODE"
                    ),
                    "finding_type": "misconfig",
                    "resource": {
                        "name": self._first(it.get("resource"), fp, "unknown"),
                        "path": fp,
                        "type": "infrastructure",
                    },
                    "references": refs,
                    "metadata": {"raw_index": i},
                }
            )
        sm = doc.get("summary", {}) if isinstance(doc.get("summary"), dict) else {}
        rep = {
            "tool": "checkov",
            "version": self._first(
                sm.get("checkov_version"), os.environ.get("CHECKOV_VERSION"), "unknown"
            ),
            "status": "OK",
            "findings": findings,
            "errors": [],
        }
        tr = {
            "tool": "checkov",
            "path": str(p),
            "present": True,
            "valid_json": True,
            "status": self._trace_status("OK", findings),
            "reason": "",
            "sha256": sha,
        }
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

    def _trivy_from_doc(
        self, doc: Dict[str, Any], scan_type: str
    ) -> List[Dict[str, Any]]:
        res = doc.get("Results", [])
        if not isinstance(res, list):
            return []
        out: List[Dict[str, Any]] = []
        for r in res:
            if not isinstance(r, dict):
                continue
            tgt = self._first(r.get("Target"), "unknown") or "unknown"
            for v in (
                r.get("Vulnerabilities", [])
                if isinstance(r.get("Vulnerabilities"), list)
                else []
            ):
                if not isinstance(v, dict):
                    continue
                out.append(
                    {
                        "id": self._first(
                            v.get("VulnerabilityID"), "TRIVY_VULN_UNKNOWN"
                        ),
                        "description": self._first(
                            v.get("Title"), v.get("Description"), "No description"
                        ),
                        "severity": self._first(v.get("Severity"), "MEDIUM"),
                        "status": "FAILED",
                        "finding_type": "vulnerability",
                        "resource": {
                            "name": self._first(v.get("PkgName"), tgt, "unknown"),
                            "path": tgt,
                            "type": "package",
                            "version": self._first(v.get("InstalledVersion"), "N/A"),
                        },
                        "references": [
                            str(x)
                            for x in (v.get("References") or [])
                            if isinstance(x, str)
                        ],
                        "fix_version": self._first(v.get("FixedVersion"), "N/A"),
                        "metadata": {
                            "scan_type": scan_type,
                            "installed_version": self._first(
                                v.get("InstalledVersion"), ""
                            ),
                            "fixed_version": self._first(v.get("FixedVersion"), ""),
                            "cvss": self._cvss(v.get("CVSS")),
                        },
                    }
                )
            for s in r.get("Secrets", []) if isinstance(r.get("Secrets"), list) else []:
                if not isinstance(s, dict):
                    continue
                st = self._to_int(s.get("StartLine"), 0)
                en = self._to_int(s.get("EndLine"), st)
                material = self._first(s.get("Match"), s.get("Code"), "") or ""
                out.append(
                    {
                        "id": self._first(s.get("RuleID"), "TRIVY_SECRET_UNKNOWN"),
                        "description": self._first(s.get("Title"), "Secret detected"),
                        "severity": self._first(s.get("Severity"), "HIGH"),
                        "status": "FAILED",
                        "finding_type": "secret",
                        "resource": {"name": tgt, "path": tgt, "type": "asset"},
                        "start_line": st,
                        "end_line": en,
                        "references": [],
                        "metadata": {
                            "scan_type": scan_type,
                            "secret_hash": self._sha256(material) if material else "",
                        },
                    }
                )
            for m in (
                r.get("Misconfigurations", [])
                if isinstance(r.get("Misconfigurations"), list)
                else []
            ):
                if not isinstance(m, dict):
                    continue
                st = (
                    "PASSED" if str(m.get("Status", "")).upper() == "PASS" else "FAILED"
                )
                out.append(
                    {
                        "id": self._first(m.get("ID"), "TRIVY_MISCONFIG_UNKNOWN"),
                        "description": self._first(
                            m.get("Title"), m.get("Message"), "No description"
                        ),
                        "severity": self._first(m.get("Severity"), "MEDIUM"),
                        "status": st,
                        "finding_type": "misconfig",
                        "resource": {
                            "name": tgt,
                            "path": self._first(
                                (m.get("CauseMetadata") or {}).get("Resource"),
                                tgt,
                                "unknown",
                            ),
                            "type": "configuration",
                        },
                        "references": [
                            str(x)
                            for x in (m.get("References") or [])
                            if isinstance(x, str)
                        ],
                        "metadata": {"scan_type": scan_type},
                    }
                )
        return out

    def _parse_trivy(self, skip=False):
        paths = {
            "fs": self.root / "shift-left/trivy/reports/raw/trivy-fs-raw.json",
            "config": self.root / "shift-left/trivy/reports/raw/trivy-config-raw.json",
        }
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
        image_files = (
            sorted(image_dir.glob("trivy-image-*-raw.json"))
            if image_dir.is_dir()
            else []
        )

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
                        ver = (
                            self._first(meta.get("Version"), ver, "unknown")
                            or "unknown"
                        )
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
        rep = {
            "tool": "trivy",
            "version": ver,
            "status": status,
            "findings": findings,
            "errors": errs,
        }
        tr = {
            "tool": "trivy",
            "path": tr_path,
            "present": present,
            "valid_json": valid,
            "status": self._trace_status(status, findings),
            "reason": ";".join(errs),
            "sha256": None,
        }
        return rep, tr

    def _parse_cloudinit(self, skip: bool = False):
        """Ingest cloud-init scanner output and convert violations to normalized findings.

        Architectural contract:
        - Cloud-init violations are FIRST-CLASS findings, identical in structure to
          Gitleaks/Checkov/Trivy findings. They enter the standard findings[] array,
          are counted in summary thresholds, and are pushed to DefectDojo.
        - resources_analyzed is PRESERVED as metadata in the golden report for
          OPA multi-signal correlation (gate_deny_intent.rego reads it directly).
        - Non-waivable violations (SSH key injection, firewall disable, remote exec)
          are marked in metadata.non_waivable=true for OPA governance enforcement.
        """
        import os as _os
        from pathlib import Path as _Path

        default_path = self.root / ".cloudsentinel" / "cloudinit_analysis.json"
        cloudinit_path = _Path(
            _os.environ.get("CLOUDINIT_ANALYSIS_JSON", str(default_path))
        )
        tool_path = str(cloudinit_path)

        if skip:
            return self._not_run("cloudinit", tool_path, "skipped_local_fast")

        if not cloudinit_path.is_file():
            # Non-blocking absence: cloud-init scanner only runs when VMs are present.
            # Treat as NOT_RUN (advisory) rather than hard failure.
            return self._not_run(
                "cloudinit", tool_path, f"missing_report:{cloudinit_path}"
            )

        sha = self._hash_file(cloudinit_path)
        doc, err = self._read_json(cloudinit_path)
        if err:
            return self._not_run(
                "cloudinit",
                tool_path,
                f"invalid_json:{cloudinit_path}",
                present=True,
                sha=sha,
            )

        resources: List[Dict[str, Any]] = doc.get("resources_analyzed", [])
        if not isinstance(resources, list):
            return self._not_run(
                "cloudinit",
                tool_path,
                "invalid_raw_structure:resources_analyzed_not_array",
                present=True,
                valid=True,
                sha=sha,
            )

        # Non-waivable rule IDs — must be kept in sync with gate_deny_intent.rego
        _NON_WAIVABLE = frozenset({
            "CS-CLOUDINIT-REMOTE-EXEC",
            "CS-MULTI-SIGNAL-ROLE-SPOOFING-V2",
            "CS-CLOUDINIT-SSH-KEY-INJECTION",
            "CS-CLOUDINIT-FIREWALL-DISABLE",
            "CS-CLOUDINIT-HARDCODED-CREDENTIALS",
        })

        findings: List[Dict[str, Any]] = []
        for resource in resources:
            if not isinstance(resource, dict):
                continue
            resource_addr = str(resource.get("resource_address", "unknown"))
            resource_file = str(resource.get("file", "unknown"))
            resource_line = int(resource.get("line", 0) or 0)
            resource_env = str(resource.get("environment", "dev"))
            cloud_init_field = str(resource.get("cloud_init_field") or "unknown")
            signals = resource.get("signals", {})

            for violation in resource.get("violations", []):
                if not isinstance(violation, dict):
                    continue

                rule_id = str(violation.get("rule", "CS-CLOUDINIT-UNKNOWN"))
                raw_sev = str(violation.get("severity", "HIGH")).upper()
                sev = self.sev_lut.get(raw_sev, "HIGH")
                description = str(
                    violation.get("message", "Cloud-init security violation")
                )
                is_non_waivable = rule_id in _NON_WAIVABLE

                findings.append({
                    "id": rule_id,
                    "description": description,
                    "file": resource_file,
                    "line": resource_line,
                    "severity": sev,
                    "status": "FAILED",
                    "category": "INFRASTRUCTURE_AS_CODE",
                    "finding_type": "cloud_init",
                    "resource": {
                        "name": resource_addr,
                        "path": resource_file,
                        "type": "vm_bootstrap",
                        "location": {
                            "start_line": resource_line,
                            "end_line": resource_line,
                        },
                    },
                    "references": [],
                    "metadata": {
                        "environment": resource_env,
                        "cloud_init_field": cloud_init_field,
                        "signals": signals,
                        "non_waivable": is_non_waivable,
                        "block": bool(violation.get("block", False)),
                    },
                })

        scanner_version = str(doc.get("schema_version", "1.0.0"))
        status = "OK" if resources else "NOT_RUN"
        rep = {
            "tool": "cloudinit",
            "version": scanner_version,
            "status": status,
            "findings": findings,
            "errors": [e for e in doc.get("summary", {}).get("parse_errors", []) if e],
        }
        tr = {
            "tool": "cloudinit",
            "path": tool_path,
            "present": True,
            "valid_json": True,
            "status": self._trace_status(status, findings),
            "reason": "",
            "sha256": sha,
        }
        return rep, tr
