#!/usr/bin/env bash
# 启动 Monica MDBX 的 MCP 服务（stdio）。MCP 客户端把这个脚本当 command 用。
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -x "$here/.venv/bin/python" ]; then
  echo "缺少 .venv：先在 $here 跑一次 uv sync" >&2
  exit 1
fi

exec "$here/.venv/bin/python" "$here/server.py"
