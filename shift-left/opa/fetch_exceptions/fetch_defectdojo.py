#!/usr/bin/env python3
"""DefectDojo API client logic for risk acceptance retrieval (fetch layer only)."""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from logging import Logger
from typing import Any, Dict, List

from .fetch_utils import sanitize_text


class DefectDojoFetchError(RuntimeError):
    """Raised when DefectDojo cannot be queried reliably."""


def _resolve_ssl_context() -> ssl.SSLContext:
    # Prefer explicit CloudSentinel bundle, then standard env overrides.
    for env_name in ("CLOUDSENTINEL_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        ca_path = os.environ.get(env_name, "").strip()
        if not ca_path:
            continue
        if not os.path.isfile(ca_path):
            raise DefectDojoFetchError(f"invalid_ca_bundle:{env_name}:{ca_path}")
        return ssl.create_default_context(cafile=ca_path)
    return ssl.create_default_context()


def _fetch_json(
    url: str, headers: Dict[str, str], timeout: int, logger: Logger
) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers=headers)
    ssl_ctx = _resolve_ssl_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        logger.error(f"DefectDojo request failed: {exc}")
        raise DefectDojoFetchError(f"request_failed:{url}") from exc
    except json.JSONDecodeError as exc:
        logger.error("DefectDojo returned malformed JSON")
        raise DefectDojoFetchError(f"invalid_json:{url}") from exc

    if not isinstance(body, dict):
        logger.error("DefectDojo response payload is not a JSON object")
        raise DefectDojoFetchError(f"invalid_payload_type:{url}")
    return body


def _resolve_user_identity(
    dojo_url: str,
    headers: Dict[str, str],
    raw_value: Any,
    user_cache: Dict[str, str],
    logger: Logger,
) -> str:
    if isinstance(raw_value, dict):
        candidate = sanitize_text(raw_value.get("username") or raw_value.get("email"))
        return candidate

    token = sanitize_text(raw_value)
    if not token:
        return ""
    if not token.isdigit():
        return token

    if token in user_cache:
        return user_cache[token]

    endpoint = f"{dojo_url}/api/v2/users/{token}/"
    try:
        user_payload = _fetch_json(endpoint, headers, 10, logger)
    except DefectDojoFetchError:
        return token

    resolved = sanitize_text(
        user_payload.get("username") or user_payload.get("email") or token
    )
    user_cache[token] = resolved
    return resolved


def _extract_finding_id(item: Any) -> str:
    if isinstance(item, int):
        return str(item)
    if isinstance(item, str):
        return sanitize_text(item) if sanitize_text(item).isdigit() else ""
    if isinstance(item, dict):
        candidate = sanitize_text(item.get("id"))
        return candidate if candidate.isdigit() else ""
    return ""


def _enrich_with_accepted_findings(
    dojo_url: str,
    headers: Dict[str, str],
    risk_acceptances: List[Dict[str, Any]],
    logger: Logger,
) -> None:
    finding_cache: Dict[str, Dict[str, Any]] = {}
    user_cache: Dict[str, str] = {}

    for ra in risk_acceptances:
        ra["owner"] = _resolve_user_identity(
            dojo_url, headers, ra.get("owner"), user_cache, logger
        )
        ra["accepted_by"] = _resolve_user_identity(
            dojo_url,
            headers,
            ra.get("accepted_by"),
            user_cache,
            logger,
        )

        raw_findings = ra.get("accepted_findings", [])
        if not isinstance(raw_findings, list) or not raw_findings:
            continue

        details: List[Dict[str, Any]] = []
        for item in raw_findings:
            finding_id = _extract_finding_id(item)
            if not finding_id:
                continue

            if finding_id not in finding_cache:
                endpoint = f"{dojo_url}/api/v2/findings/{finding_id}/"
                finding_payload = _fetch_json(endpoint, headers, 10, logger)
                if isinstance(finding_payload, dict) and finding_payload:
                    finding_cache[finding_id] = finding_payload

            if finding_id in finding_cache:
                details.append(finding_cache[finding_id])

        if details:
            ra["accepted_finding_details"] = details


def fetch_risk_acceptances(
    dojo_url: str, dojo_api_key: str, dojo_engagement_id: str, logger: Logger
) -> List[Dict[str, Any]]:
    if not dojo_url or not dojo_api_key:
        raise DefectDojoFetchError("missing_credentials")

    headers = {
        "Authorization": f"Token {dojo_api_key}",
        "Accept": "application/json",
    }

    start_url = f"{dojo_url}/api/v2/findings/?risk_accepted=true&limit=100"
    if dojo_engagement_id:
        start_url += f"&engagement={dojo_engagement_id}"

    logger.info(f"[fetch-exceptions] Fetching risk accepted findings from {start_url}")

    results: List[Dict[str, Any]] = []
    current: str = start_url
    while current:
        body = _fetch_json(current, headers, 20, logger)
        page = body.get("results", [])
        if not isinstance(page, list):
            raise DefectDojoFetchError(f"invalid_results_array:{current}")
        results.extend(item for item in page if isinstance(item, dict))
        current = sanitize_text(body.get("next"))

    logger.info(f"[fetch-exceptions] Fetched {len(results)} risk-accepted finding(s)")

    ra_map: Dict[str, Dict[str, Any]] = {}
    user_cache: Dict[str, str] = {}

    for finding in results:
        accepted_risks = finding.get("accepted_risks", [])
        if not isinstance(accepted_risks, list) or len(accepted_risks) == 0:
            if finding.get("risk_accepted"):
                legacy_ra_id = f"legacy_ra_{finding.get('id')}"
                if legacy_ra_id not in ra_map:
                    ra_map[legacy_ra_id] = {
                        "id": legacy_ra_id,
                        "owner": "legacy_admin",
                        "accepted_by": "legacy_admin",
                        "expiration_date": None,
                        "decision": "A",
                        "status": "Accepted",
                        "created": finding.get("created"),
                        "updated": finding.get("updated"),
                        "accepted_finding_details": [],
                    }
                ra_map[legacy_ra_id]["accepted_finding_details"].append(finding)
            continue

        for ra in accepted_risks:
            if not isinstance(ra, dict):
                continue
            ra_id = str(ra.get("id", ""))
            if not ra_id:
                continue

            if ra_id not in ra_map:
                ra_map[ra_id] = dict(ra)
                ra_map[ra_id]["accepted_finding_details"] = []
                ra_map[ra_id]["owner"] = _resolve_user_identity(
                    dojo_url, headers, ra.get("owner"), user_cache, logger
                )
                ra_map[ra_id]["accepted_by"] = _resolve_user_identity(
                    dojo_url, headers, ra.get("accepted_by"), user_cache, logger
                )

            ra_map[ra_id]["accepted_finding_details"].append(finding)

    final_ras = list(ra_map.values())
    logger.info(
        f"[fetch-exceptions] Extracted {len(final_ras)} unique Risk Acceptance(s) from findings"
    )
    return final_ras
