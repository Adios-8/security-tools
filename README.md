@"

\# Security Tools - 安全工具集



本项目包含两个独立的命令行安全分析工具，基于 Python 开发。



\## 📁 项目列表



| 工具 | 功能 | 技术栈 |

|------|------|--------|

| 日志审计工具 (log-auditor) | 检测暴力破解、异常时段登录 | Python 标准库 |

| 供应链扫描器 (dep-scanner) | 扫描 npm 依赖漏洞，生成 HTML 报告 | Python + requests + OSV API |



\---



\## 🔧 日志审计工具 (log-auditor)



\### 功能

\- 检测同一 IP 在 10 分钟内失败登录 ≥ 5 次的暴力破解行为

\- 检测 00:00-06:00 时段的异常登录

\- 输出 JSON 格式结果



\### 使用方法

\\`\\`\\`bash

cd log-auditor



\# 测试模式（自动生成测试日志）

python auditor.py --test



\# 分析指定日志文件

python auditor.py --file security.log



\# 输出到 JSON 文件

python auditor.py --file security.log --output result.json

\\`\\`\\`



\---



\## 🔧 供应链扫描器 (dep-scanner)



\### 功能

\- 解析 package.json，提取依赖

\- 调用 OSV API 查询已知漏洞

\- 生成 HTML 可视化报告



\### 使用方法

\\`\\`\\`bash

cd dep-scanner



\# 安装依赖

pip install requests



\# 扫描当前目录

python scanner.py



\# 指定项目路径和报告名

python scanner.py --path /path/to/project --output my\_report.html

\\`\\`\\`



\---



\## 📄 许可证



MIT



\## 👤 作者



\[Adios-8](https://github.com/Adios-8)

"@ | Out-File -FilePath README.md -Encoding utf8

