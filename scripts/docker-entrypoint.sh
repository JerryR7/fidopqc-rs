#!/bin/bash
set -e

# 如果 AUTO_GENERATE_CERTS 設置為 true，則生成證書
if [ "$AUTO_GENERATE_CERTS" = "true" ]; then
    echo "自動生成證書..."
    /app/scripts/generate_certs.sh
fi

# 執行 quantum-safe-proxy 命令
exec "$@"
