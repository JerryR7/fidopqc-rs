#!/bin/bash
# 清理所有證書的腳本

set -e  # 遇到錯誤立即退出

# 設置目錄
CERTS_DIR="certs"

# 確認操作
echo "警告：這將刪除 ${CERTS_DIR} 目錄中的所有證書。"
echo "您確定要繼續嗎？(y/n)"
read -r confirm

if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
    echo "操作已取消。"
    exit 0
fi

# 清理所有證書
echo "清理所有證書..."
rm -rf ${CERTS_DIR}
echo "清理完成。"
