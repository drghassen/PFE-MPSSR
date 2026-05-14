#!/usr/bin/env python3
"""Compatibility wrapper for the CloudSentinel cloud-init scanner.

The implementation lives in `cloudsentinel_cloudinit/` to keep parsing,
pattern loading, analysis, and CLI concerns separated.
"""

from __future__ import annotations

import sys
from pathlib import Path

SCANNER_DIR = Path(__file__).resolve().parent
if str(SCANNER_DIR) not in sys.path:
    sys.path.insert(0, str(SCANNER_DIR))

from cloudsentinel_cloudinit import DEFAULT_PATTERN_DB_PATH, analyze_terraform
from cloudsentinel_cloudinit.cli import main, parse_args

__all__ = [
    "DEFAULT_PATTERN_DB_PATH",
    "analyze_terraform",
    "main",
    "parse_args",
]


if __name__ == "__main__":
    raise SystemExit(main())
