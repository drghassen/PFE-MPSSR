#!/usr/bin/env python3
"""DefectDojo API client logic for risk acceptance retrieval."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from logging import Logger
from typing import Any, Dict, List

from .fetch_utils import safe_str


def _fetch_json(url: str, headers: Dict[str, str], timeout: int, logger: Logger) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as e:
        logger.error(f"DefectDojo request failed: {e}")
        return {}
    except json.JSONDecodeError:
        logger.error("DefectDojo returned malformed JSON")
        return {}
    return body if isinstance(body, dict) else {}


def _enrich_with_accepted_findings(
    dojo_url: str,
    headers: Dict[str, str],
    risk_acceptances: List[Dict[str, Any]],
    logger: Logger,
) -> None:
    finding_cache: Dict[str, Dict[str, Any]] = {}
    enriched_count = 0

    for ra in risk_acceptances:
        raw_ids = ra.get("accepted_findings", [])
        if not isinstance(raw_ids, list) or not raw_ids:
            continue

        details: List[Dict[str, Any]] = []
        for finding_id in raw_ids:
            fid = safe_str(finding_id)
            if not fid:
                continue

            if fid not in finding_cache:
                endpoint = f"{dojo_url}/api/v2/findings/{fid}/"
                finding = _fetch_json(endpoint, headers, 10, logger)
                if finding:
                    finding_cache[fid] = finding

            if fid in finding_cache:
                details.append(finding_cache[fid])

        if details:
            ra["accepted_finding_details"] = details
            enriched_count += 1

    if enriched_count:
        logger.info(f"Enriched {enriched_count} risk acceptances with accepted finding details")


def fetch_risk_acceptances(dojo_url: str, dojo_api_key: str, logger: Logger) -> List[Dict[str, Any]]:
    if not dojo_url or not dojo_api_key:
        logger.info("DefectDojo credentials missing; running with empty payload")
        return []

    endpoint = f"{dojo_url}/api/v2/risk_acceptance/"
    headers = {
        "Authorization": f"Token {dojo_api_key}",
        "Accept": "application/json",
    }

    results: List[Dict[str, Any]] = []
    next_url = endpoint

    while next_url:
        body = _fetch_json(next_url, headers, 15, logger)
        if not body:
            return []

        page = body.get("results", [])
        if isinstance(page, list):
            results.extend([x for x in page if isinstance(x, dict)])

        raw_next = body.get("next")
        next_url = safe_str(raw_next)

    _enrich_with_accepted_findings(dojo_url, headers, results, logger)
    logger.info(f"Fetched {len(results)} risk acceptances from DefectDojo")
    return results
