# Security Tools

[![Python](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

两个独立的安全分析命令行工具，基于 Python 开发，可直接运行或通过 Docker 一键部署。

---

## 快速开始

```bash
# 1. 克隆仓库
git clone https://github.com/Adios-8/security-tools.git
cd security-tools

# 2. 安装依赖（仅扫描器需要）
pip install requests

# 3. 运行
python dep-scanner/scanner.py          # 扫描漏洞（自动创建示例 package.json）
python log-auditor/auditor.py --test   # 审计日志（自动生成测试数据）
```

---

## 工具概览

| | 供应链漏洞扫描器 | 日志安全审计工具 |
|------|:---:|:---:|
| 入口 | `dep-scanner/scanner.py` | `log-auditor/auditor.py` |
| 用途 | 检测项目依赖的已知 CVE | 发现暴力破解和异常登录 |
| 输入 | `package.json` | 安全日志文件 |
| 输出 | 控制台 + HTML 报告 | 控制台 + JSON 报告 |
| 外部依赖 | `requests` | **无（纯标准库）** |
| API | OSV.dev | — |

---

## 供应链漏洞扫描器

### 核心特性

- 解析 `package.json`，自动合并 `dependencies` + `devDependencies`
- 逐包查询 OSV 漏洞数据库，获取 CVE / GHSA 编号和 CVSS 评分
- **智能缓存**：`cache.json` 本地持久化，1 小时内重复查询直接命中
- **自动重试**：`urllib3.Retry` 机制，3 次指数退避，覆盖 429/5xx 状态码
- 无 `package.json` 时自动生成示例文件，方便快速体验

### 使用

```bash
python scanner.py                              # 扫描当前目录
python scanner.py --path ~/my-project          # 指定项目路径
python scanner.py --output scan-result.html    # 自定义报告名
```

### 控制台输出示例

```
[*] 项目路径: /home/adios/project
[*] 共发现 4 个依赖包
[*] 缓存条目: 4，有效期: 60 分钟

  [1/4] 检查 express@4.18.0 ... 发现 2 个漏洞  [CACHE HIT]
  [2/4] 检查 lodash@4.17.21 ... 发现 3 个漏洞  [CACHE HIT]
  [3/4] 检查 axios@1.6.0 ... 发现 19 个漏洞   [API CALL]
  [4/4] 检查 qs@6.5.2 ... 发现 2 个漏洞      [CACHE HIT]

[*] 缓存命中 3 次，API 调用 1 次
============================================================
  扫描完成 —— 共 4 个包，4 个受影响，漏洞总数 26
============================================================

[PACKAGE] express@4.18.0
  [VULN] GHSA-qw6h-vgh9-j6wx  [CVSS CVSS:3.1/AV:N/...]  express vulnerable to XSS...
  [VULN] GHSA-rv95-896h-c2vc  [CVSS CVSS:3.1/AV:N/...]  Express.js Open Redirect...
```

### 报告预览

生成的 `report.html` 包含漏洞表格，支持按包名、CVE 编号、严重等级排序查看，漏洞 ID 可点击跳转到 NVD / GitHub Advisory 详情页。

---

## 日志安全审计工具

### 核心特性

- **暴力破解检测**：滑动窗口算法，同一 IP 在 10 分钟内失败登录 ≥ 5 次触发告警，重叠窗口自动合并
- **异常时段检测**：标记 00:00–06:00 之间的所有登录记录
- **白名单过滤**：支持按 IP 或用户名排除误报，`#` 开头行为注释
- 零第三方依赖，任何有 Python 3 的环境都能直接运行
- `--test` 模式内置 22 条覆盖正常/暴力/凌晨场景的测试日志

### 使用

```bash
python auditor.py                                   # 读取 security.log
python auditor.py --test                            # 生成测试数据并分析
python auditor.py --file /var/log/auth.log          # 指定日志文件
python auditor.py --output result.json              # 导出 JSON 报告
python auditor.py --whitelist whitelist.txt          # 启用白名单过滤
```

### 白名单文件格式

```
# 内部扫描器 IP
10.0.0.5
192.168.1.1

# 运维人员账号
operator
admin
```

### 日志格式支持

```
[2026-05-16 03:25:10] Failed password for admin from 192.168.1.100
[2026-05-16 03:25:15] Failed password for invalid user root from 192.168.1.100
[2026-05-16 09:30:00] Accepted password for admin from 10.0.0.1
```

### JSON 输出示例

```json
{
  "scan_time": "2026-05-16 20:28:36",
  "summary": {
    "total_records": 22,
    "total_anomalies": 12,
    "off_hours_count": 10,
    "brute_force_count": 2
  },
  "anomalies": [
    {
      "type": "brute_force",
      "ip": "192.168.1.100",
      "count": 7,
      "first_attempt": "2026-05-16 03:20:00",
      "last_attempt": "2026-05-16 03:23:00",
      "detail": "IP 192.168.1.100 在 10 分钟内 失败登录 7 次（阈值 5 次）"
    }
  ]
}
```

---

## Docker 部署

```bash
# 构建
docker build -t security-tools .

# 漏洞扫描
docker run --rm -v "$PWD:/data" security-tools scanner --path /data

# 日志审计（测试模式，无需挂载）
docker run --rm security-tools auditor --test

# 日志审计（挂载日志目录）
docker run --rm -v "$PWD/logs:/data" security-tools auditor --file /data/auth.log
```

或使用 docker-compose：

```bash
docker compose run dep-scanner        # 漏洞扫描
docker compose run log-auditor        # 日志审计
docker compose run log-auditor-test   # 日志审计（测试模式）
```

---

## 项目结构

```
security-tools/
├── Dockerfile
├── docker-compose.yml
├── entrypoint.sh
├── README.md
├── dep-scanner/
│   └── scanner.py
└── log-auditor/
    └── auditor.py
```

---

## 环境要求

- Python 3.8+
- （仅扫描器）`pip install requests`
- （可选）Docker 24+

---

## 许可证

MIT © [Adios-8](https://github.com/Adios-8)
