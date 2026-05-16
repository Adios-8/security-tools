#!/bin/sh
# 安全工具统一入口 —— 根据第一个参数选择运行 scanner 或 auditor

TOOL="$1"
shift

case "$TOOL" in
    scanner)
        exec python /app/scanner.py "$@"
        ;;
    auditor)
        exec python /app/auditor.py "$@"
        ;;
    *)
        echo "用法: docker run ... <工具名> [参数]"
        echo ""
        echo "可用工具:"
        echo "  scanner   供应链漏洞扫描器"
        echo "  auditor   日志安全审计工具"
        echo ""
        echo "示例:"
        echo "  docker run ... scanner --path /data --output /data/report.html"
        echo "  docker run ... auditor --file /data/security.log"
        echo "  docker run ... auditor --test"
        exit 1
        ;;
esac
