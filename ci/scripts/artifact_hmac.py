#!/usr/bin/env python3
"""
artifact_hmac.py — HMAC-SHA256 sign/verify for CI artifact integrity.

Usage:
  python3 ci/scripts/artifact_hmac.py sign   <artifact>
  python3 ci/scripts/artifact_hmac.py verify <artifact>

Secret key is read from CLOUDSENTINEL_HMAC_SECRET (masked+protected CI/CD variable).
Sidecar written to <artifact>.hmac (hex HMAC-SHA256, newline-terminated).

Exit codes: 0 = OK, 1 = integrity failure, 2 = usage/config error.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sys
from pathlib import Path


def _read_key() -> bytes:
    secret = os.environ.get("CLOUDSENTINEL_HMAC_SECRET", "")
    if not secret:
        print("[artifact-hmac][ERROR] CLOUDSENTINEL_HMAC_SECRET is not set.", file=sys.stderr)
        sys.exit(2)
    return secret.encode("utf-8")


def _compute(key: bytes, artifact: Path) -> str:
    return hmac.new(key, artifact.read_bytes(), hashlib.sha256).hexdigest()


def sign(artifact: Path) -> None:
    key = _read_key()
    digest = _compute(key, artifact)
    sidecar = Path(str(artifact) + ".hmac")
    sidecar.write_text(digest + "\n", encoding="ascii")
    print(f"[artifact-hmac] Signed   {artifact} → {sidecar}")


def verify(artifact: Path) -> None:
    key = _read_key()
    sidecar = Path(str(artifact) + ".hmac")
    if not sidecar.is_file():
        print(f"[artifact-hmac][ERROR] HMAC sidecar missing: {sidecar}", file=sys.stderr)
        print("[artifact-hmac][ERROR] Artifact may have been tampered or signing step did not run.", file=sys.stderr)
        sys.exit(1)
    expected = _compute(key, artifact)
    actual = sidecar.read_text(encoding="ascii").strip()
    # compare_digest is constant-time: prevents timing oracle on the secret.
    if not hmac.compare_digest(expected, actual):
        print(f"[artifact-hmac][ERROR] HMAC mismatch — {artifact} integrity check FAILED", file=sys.stderr)
        sys.exit(1)
    print(f"[artifact-hmac] Verified {artifact} (HMAC-SHA256 OK)")


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <sign|verify> <artifact>", file=sys.stderr)
        sys.exit(2)

    mode, path = sys.argv[1], sys.argv[2]
    artifact = Path(path)

    if not artifact.is_file():
        print(f"[artifact-hmac][ERROR] File not found: {artifact}", file=sys.stderr)
        sys.exit(2)

    if mode == "sign":
        sign(artifact)
    elif mode == "verify":
        verify(artifact)
    else:
        print(f"[artifact-hmac][ERROR] Unknown mode '{mode}' — use sign or verify", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
