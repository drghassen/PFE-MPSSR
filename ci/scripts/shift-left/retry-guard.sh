#!/usr/bin/env bash
set -euo pipefail

chmod +x shift-left/ci/retry-guard.sh
bash shift-left/ci/retry-guard.sh
