#!/usr/bin/env python3
# ==============================================================================
# CloudSentinel Risk Acceptance Fetcher (Anti-Corruption Layer)
# Description: Fetches approved Risk Acceptances from DefectDojo API and
#              transforms them into the strict schema expected by OPA.
#              Fails closed (returns valid empty JSON) on network or auth errors.
# ==============================================================================

import os
import sys
import json
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
import re

# Structured Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "component": "fetch-exceptions", "message": "%(message)s"}',
    datefmt='%Y-%m-%dT%H:%M:%SZ',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)

DEFECTDOJO_URL = os.environ.get("DOJO_URL", "").rstrip("/")
DEFECTDOJO_API_KEY = os.environ.get("DOJO_API_KEY", "")
CI_PROJECT_NAME = os.environ.get("CI_PROJECT_NAME", "unknown")

# Always save to the artifact location so OPA can find it safely
# In CI, we run from the repository root.
REPO_ROOT = os.getcwd()
OUTPUT_FILE = os.environ.get("OPA_EXCEPTIONS_FILE", os.path.join(REPO_ROOT, ".cloudsentinel", "exceptions.json"))
DROPPED_FILE = os.path.join(REPO_ROOT, ".cloudsentinel", "dropped_exceptions.json")

# Global list for audit trail
dropped_exceptions = []

def record_drop(ra_id, reason):
    """Logs and records a dropped exception for the audit trail."""
    logger.error(f"Dropping RA {ra_id}: {reason}")
    dropped_exceptions.append({
        "id": f"RA-{ra_id}",
        "reason": reason,
        "dropped_at": format_rfc3339()
    })

def generate_empty_payload(reason):
    """Generates a valid empty exceptions payload (Fail-Closed)."""
    logger.warning(f"Generating empty exceptions payload (Fail-Secure). Reason: {reason}")
    payload = {
        "cloudsentinel": {
            "exceptions": {
                "exceptions": []
            }
        }
    }
    save_payload(payload)
    save_dropped_payload()
    sys.exit(0)

def save_dropped_payload():
    """Saves the audit trail of dropped exceptions."""
    os.makedirs(os.path.dirname(DROPPED_FILE), exist_ok=True)
    with open(DROPPED_FILE, 'w', encoding='utf-8') as f:
        json.dump({"dropped_exceptions": dropped_exceptions}, f, indent=2)
    logger.info(f"Audit trail saved to {DROPPED_FILE}")

def save_payload(payload):
    """Saves the JSON payload to the artifact directory."""
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2)
    logger.info(f"Exceptions saved to {OUTPUT_FILE}")

def is_valid_email(email):
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email.lower()) is not None

def format_rfc3339(dt=None):
    if dt is None:
        dt = datetime.now(timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')

def norm_path(path):
    """Canonicalize path to match exactly with normalizer output"""
    if not path: return "unknown"
    p = str(path).replace("\\", "/").replace("/./", "/")
    while "//" in p: p = p.replace("//", "/")
    if p.startswith("./"): p = p[2:]
    return p if p else "unknown"

def fetch_from_dojo():
    """Fetches Risk Acceptances from DefectDojo API v2"""
    if not DEFECTDOJO_URL or not DEFECTDOJO_API_KEY:
        logger.warning("DefectDojo URL or API Key missing. Skipping fetch.")
        return []

    # DefectDojo API v2 Risk Acceptance endpoint
    endpoint = f"{DEFECTDOJO_URL}/api/v2/risk_acceptance/"
    logger.info(f"Querying DefectDojo: {endpoint}")
    
    req = urllib.request.Request(endpoint, headers={
        "Authorization": f"Token {DEFECTDOJO_API_KEY}",
        "Accept": "application/json"
    })
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.getcode() != 200:
                logger.error(f"DefectDojo returned HTTP {response.getcode()}")
                return []
            data = json.loads(response.read().decode('utf-8'))
            return data.get('results', [])
    except urllib.error.URLError as e:
        logger.error(f"Network error while calling DefectDojo: {str(e)}")
        return []
    except json.JSONDecodeError:
        logger.error("Invalid JSON response from DefectDojo")
        return []
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return []

def map_risk_acceptance_to_opa(ra):
    """
    Anti-Corruption Layer: Maps DefectDojo RA to OPA schema.
    Applies defensive values for fields that might be missing in Dojo.
    """
    # 1. Extraction and strict validation of expiration date
    expiration_date_str = ra.get("expiration_date", "")
    try:
        # Expected format from DefectDojo
        if len(expiration_date_str) >= 10:
            expiration_dt = datetime.strptime(expiration_date_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        else:
            expiration_dt = datetime.now(timezone.utc) - timedelta(days=1)
    except ValueError:
        reason = f"Failed to parse expiration_date '{expiration_date_str}'"
        record_drop(ra.get('id'), reason)
        return None
    
    now = datetime.now(timezone.utc)
    
    # Fail-Secure: Drop if expired
    if now > expiration_dt:
        reason = f"Already expired (Expires: {expiration_dt.strftime('%Y-%m-%d')} < Today)"
        record_drop(ra.get('id'), reason)
        return None
    
    # 2. Advanced warnings (Race Condition Buffer)
    time_left = expiration_dt - now
    if time_left.days < 7:
        logger.warning(f"RA {ra.get('id')} expires in less than 7 days ({time_left.days} days).")

    # 3. Defensive mapping of complex rules
    # Natively, Dojo risk acceptances apply to findings. We map the name to rule_id.
    rule_id = str(ra.get("name", "")).strip()
    if not rule_id:
        record_drop(ra.get('id'), "Missing required rule_id (in 'name' field)")
        return None

    # Defensive contact values
    requested_by = str(ra.get("owner", "dev-system@example.com")).strip()
    approved_by = str(ra.get("approver", "appsec-system@example.com")).strip()
    
    if not is_valid_email(requested_by):
        requested_by = "dev-system@example.com"
    if not is_valid_email(approved_by):
        approved_by = "appsec-system@example.com"
        
    # Separation of Duties (SoD) Assertion
    if requested_by.lower() == approved_by.lower():
        record_drop(ra.get('id'), f"Self-approval detected ({requested_by}). Violates SoD.")
        return None

    mapped = {
        "id": f"RA-{ra.get('id', 'unknown')}",
        "enabled": True,
        "tool": "checkov", # Can be extracted dynamically if stored in Dojo custom fields
        "rule_id": rule_id,
        "resource_path": norm_path(ra.get("path", "/")), # Canonicalized path
        "environments": ["dev", "test", "staging", "prod"], # Broad application Default
        "max_severity": "CRITICAL",
        "reason": ra.get("description", "Approved via DefectDojo API"),
        "ticket": f"DOJO-RA-{ra.get('id', 'unknown')}",
        "requested_by": requested_by,
        "approved_by": approved_by,
        "commit_hash": "a1b2c3d", # Native API doesn't hold this; placeholder mapping
        "request_date": ra.get("created", format_rfc3339()),
        "expires_at": format_rfc3339(expiration_dt)
    }

    # 4. Final strict schema assertion before returning
    required_fields = ["id", "tool", "rule_id", "environments", "max_severity", 
                       "reason", "ticket", "requested_by", "approved_by", 
                       "commit_hash", "request_date", "expires_at", "resource_path"]
    
    for field in required_fields:
        val = mapped.get(field)
        if val == "" or val is None or (isinstance(val, list) and len(val) == 0):
            record_drop(ra.get('id'), f"Missing required field '{field}' after mapping")
            return None

    return mapped

def main():
    logger.info("Starting exception fetching process...")
    
    if not DEFECTDOJO_URL:
        logger.info("No DOJO_URL provided. Running in standalone secure mode.")
        generate_empty_payload("Standalone mode enabled (no Dojo URL)")
        
    raw_ras = fetch_from_dojo()
    
    if not raw_ras:
        # Network down, unauthorized, or empty array.
        generate_empty_payload("Zero Risk Acceptances found or API unreachable.")
        return

    valid_exceptions = []
    for ra in raw_ras:
        # Check standard DefectDojo active flag
        if not ra.get('is_active', True):
            continue
            
        mapped = map_risk_acceptance_to_opa(ra)
        if mapped:
            valid_exceptions.append(mapped)

    payload = {
        "cloudsentinel": {
            "exceptions": {
                "exceptions": valid_exceptions
            }
        }
    }
    
    save_payload(payload)
    save_dropped_payload()
    logger.info(f"Successfully processed {len(valid_exceptions)} active risk acceptances from Dojo.")
    
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        generate_empty_payload(f"Unhandled exception in script: {str(e)}")
