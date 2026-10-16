#!/usr/bin/env bash
# Forwarding build script for QNX from repo root
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/sbc_agent/build_qnx.sh" "$@"
