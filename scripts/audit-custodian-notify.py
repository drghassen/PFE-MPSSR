"""
# AGENT TASK: Cloud Custodian Policy — Notification & Observability Audit
[...coller le prompt ici...]
"""

import yaml
import json
import os
from pathlib import Path

MUTATING_ACTIONS = {
    'tag', 'set-firewall-rules', 'delete', 'stop', 'put-metric',
    'auto-tag-user', 'mark-for-op', 'network-interface'
}

def audit_policy(file_path, policy):
    actions = policy.get('actions', [])
    action_types = {a.get('type') for a in actions}
    
    has_mutating = bool(action_types & MUTATING_ACTIONS)
    has_notify = 'notify' in action_types
    has_webhook = 'webhook' in action_types
    has_post_finding = 'post-finding' in action_types
    
    if has_mutating and not any([has_notify, has_webhook, has_post_finding]):
        return {
            "file": str(file_path),
            "policy_name": policy['name'],
            "resource_type": policy['resource'],
            "has_mutating_actions": True,
            "has_notify": False,
            "has_webhook": False,
            "has_post_finding": False,
            "status": "FAIL",
            "rule_id": "CUSTODIAN-NOTIFY-001",
            "severity": "MEDIUM",
            "remediation": "Add a 'notify' action...",
            "suggested_patch": { ... }
        }
    return None

# ...parcourir les fichiers YAML...