"""CLI entrypoint for the CloudSentinel cloud-init scanner."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List

from .analyzer import analyze_terraform
from .patterns import DEFAULT_PATTERN_DB_PATH


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CloudSentinel cloud-init scanner")
    parser.add_argument(
        "--terraform-dir",
        default=".",
        help="Terraform root directory to analyze",
    )
    parser.add_argument(
        "--output",
        default=".cloudsentinel/cloudinit_analysis.json",
        help="Output JSON path",
    )
    parser.add_argument(
        "--default-env",
        default="dev",
        help="Fallback environment when tags do not include Environment/env",
    )
    parser.add_argument(
        "--pattern-db",
        default=str(DEFAULT_PATTERN_DB_PATH),
        help="Local JSON pattern database for malicious cloud-init bootstrap behavior",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    repo_root = Path.cwd()
    terraform_dir = (repo_root / args.terraform_dir).resolve()
    output_path = (repo_root / args.output).resolve()

    if not terraform_dir.exists() or not terraform_dir.is_dir():
        print(
            f"[cloudinit-scan][ERROR] terraform dir not found: {terraform_dir}",
            file=sys.stderr,
        )
        return 2

    analysis = analyze_terraform(
        terraform_dir=terraform_dir,
        repo_root=repo_root,
        default_env=args.default_env,
        pattern_db_path=Path(args.pattern_db).resolve(),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(analysis, handle, indent=2)

    summary = analysis.get("summary", {})
    print(
        "[cloudinit-scan] resources={resources} violations={violations} blocking={blocking}".format(
            resources=summary.get("total_resources", 0),
            violations=summary.get("total_violations", 0),
            blocking=summary.get("blocking_violations", 0),
        )
    )
    return 0
