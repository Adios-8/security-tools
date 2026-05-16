# Security Tools —— 安全工具集

两个独立的安全分析工具，基于 Python 开发，可直接运行或通过 Docker 部署。

---

## 项目列表

| 工具 | 文件 | 功能 | 依赖 |
|------|------|------|------|
| 供应链漏洞扫描器 | `dep-scanner/scanner.py` | 扫描 npm 依赖漏洞，生成 HTML 报告 | requests |
| 日志安全审计工具 | `log-auditor/auditor.py` | 检测暴力破解与异常时段登录 | 纯标准库 |

---

## 供应链漏洞扫描器

### 功能

- 解析 `package.json`，提取 dependencies + devDependencies
- 调用 [OSV API](https://api.osv.dev/v1/query) 查询每个依赖的已知漏洞
- 内置请求重试机制（3 次重试，指数退避，覆盖 429/5xx）
- 本地缓存（`cache.json`），1 小时内重复查询直接命中，减少 API 调用
- 控制台输出漏洞摘要，同时生成带样式的 `report.html`
- 无 `package.json` 时自动创建示例文件

### 使用方法

```bash
cd dep-scanner

# 安装依赖
pip install requests

# 扫描当前目录
python scanner.py

# 指定项目路径
python scanner.py --path /path/to/project

# 自定义报告路径
python scanner.py --path /path/to/project --output my_report.html
```

### 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--path` | `.` | 项目路径（含 package.json） |
| `--output` | `report.html` | HTML 报告输出路径 |

---

## 日志安全审计工具

### 功能

- 解析安全日志，支持两种运行模式（文件 / 测试数据生成）
- **暴力破解检测**：同一 IP 在 10 分钟内失败登录 ≥ 5 次（滑动窗口 + 窗口合并算法）
- **异常时段检测**：登录时间在 00:00–06:00 之间
- **白名单过滤**：通过外部文件排除指定 IP 或用户名的告警
- 输出 JSON 格式报告，可选写入文件
- 零第三方依赖，纯 Python 标准库

### 使用方法

```bash
cd log-auditor

# 测试模式（自动生成测试日志）
python auditor.py --test

# 分析指定日志文件
python auditor.py --file security.log

# 输出到 JSON 文件
python auditor.py --file security.log --output result.json

# 使用白名单过滤
python auditor.py --file security.log --whitelist whitelist.txt
```

### 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--file` | `security.log` | 日志文件路径 |
| `--test` | — | 生成测试数据并分析（忽略 --file） |
| `--output` | — | JSON 报告输出路径（可选） |
| `--whitelist` | — | 白名单文件，每行一个 IP 或用户名（`#` 为注释） |

### 日志格式

```
[2026-05-16 03:25:10] Failed password for admin from 192.168.1.100
[2026-05-16 03:25:15] Failed password for invalid user root from 192.168.1.100
[2026-05-16 09:30:00] Accepted password for admin from 10.0.0.1
```

支持 `Failed` / `Accepted`，支持 `invalid user` 前缀。

---

## Docker 部署

### 构建镜像

```bash
docker build -t security-tools .
```

### 运行

```bash
# 漏洞扫描
docker run --rm -v "$PWD:/data" security-tools scanner --path /data --output /data/report.html

# 日志审计（测试模式）
docker run --rm security-tools auditor --test

# 日志审计（文件模式）
docker run --rm -v "$PWD/logs:/data" security-tools auditor --file /data/security.log
```

### docker-compose

```bash
# 漏洞扫描
docker compose run dep-scanner

# 日志审计
docker compose run log-auditor

# 日志审计（测试模式）
docker compose run log-auditor-test
```

---

## 项目结构

```
security-tools/
├── Dockerfile
├── docker-compose.yml
├── entrypoint.sh              # 容器统一入口
├── README.md
│
├── dep-scanner/
│   └── scanner.py             # 供应链漏洞扫描器
│
└── log-auditor/
    └── auditor.py             # 日志安全审计工具
```

---

## 许可证

MIT

## 作者

[Adios-8](https://github.com/Adios-8)
