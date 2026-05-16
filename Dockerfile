FROM python:3.13-slim

LABEL org.opencontainers.image.description="安全工具集 —— 供应链漏洞扫描 + 日志审计"

# 安装依赖（auditor.py 纯标准库，scanner.py 需要 requests）
RUN pip install --no-cache-dir requests

# 复制工具和入口脚本
COPY dep-scanner/scanner.py /app/scanner.py
COPY log-auditor/auditor.py   /app/auditor.py
COPY entrypoint.sh            /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

WORKDIR /data
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["--help"]
