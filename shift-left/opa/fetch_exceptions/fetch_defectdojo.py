#!/usr/bin/env python3
"""DefectDojo API client logic for risk acceptance retrieval (fetch layer only)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from logging import Logger
from typing import Any, Dict, List

from .fetch_utils import sanitize_text


class DefectDojoFetchError(RuntimeError):
    """Raised when DefectDojo cannot be queried reliably."""


def _fetch_json(url: str, headers: Dict[str, str], timeout: int, logger: Logger) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
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

    for ra in risk_acceptances:
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


def fetch_risk_acceptances(dojo_url: str, dojo_api_key: str, logger: Logger) -> List[Dict[str, Any]]:
    if not dojo_url or not dojo_api_key:
        raise DefectDojoFetchError("missing_credentials")

    headers = {
        "Authorization": f"Token {dojo_api_key}",
        "Accept": "application/json",
    }

    endpoint = f"{dojo_url}/api/v2/risk_acceptance/"
    results: List[Dict[str, Any]] = []
    next_url = endpoint

    while next_url:
        body = _fetch_json(next_url, headers, 15, logger)
        page = body.get("results", [])
        if not isinstance(page, list):
            raise DefectDojoFetchError(f"invalid_results_array:{next_url}")

        for item in page:
            if isinstance(item, dict):
                results.append(item)

        next_url = sanitize_text(body.get("next"))

    _enrich_with_accepted_findings(dojo_url, headers, results, logger)
    logger.info(f"Fetched {len(results)} risk acceptances from DefectDojo")
    return results
