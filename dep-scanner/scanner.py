#!/usr/bin/env python3
"""供应链漏洞扫描器 —— 解析 package.json，通过 OSV API 查询已知漏洞，生成 HTML 报告。"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
REQUEST_TIMEOUT = 30  # 秒
MAX_RETRIES = 3
RETRY_BACKOFF = 1.0  # 指数退避基数
CACHE_TTL = 3600  # 缓存有效期（秒）


# ---------------------------------------------------------------------------
# 工具：带重试的 HTTP 会话
# ---------------------------------------------------------------------------
def build_session() -> requests.Session:
    retry = Retry(
        total=MAX_RETRIES,
        backoff_factor=RETRY_BACKOFF,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods={"POST"},
    )
    adapter = HTTPAdapter(max_retries=retry)
    s = requests.Session()
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


# ---------------------------------------------------------------------------
# 缓存管理
# ---------------------------------------------------------------------------
def _cache_path() -> Path:
    return Path(__file__).resolve().parent / "cache.json"


def _load_cache() -> dict:
    cp = _cache_path()
    if not cp.exists():
        return {}
    try:
        with open(cp, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"  [WARN] 缓存文件损坏，将重建: {exc}")
        return {}


def _save_cache(cache: dict) -> None:
    cp = _cache_path()
    try:
        with open(cp, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except OSError as exc:
        print(f"  [WARN] 无法写入缓存文件: {exc}")


def _cache_key(name: str, version: str) -> str:
    return f"{name}@{version}"


def _cache_get(cache: dict, name: str, version: str) -> list | None:
    key = _cache_key(name, version)
    entry = cache.get(key)
    if entry is None:
        return None
    if time.time() - entry["timestamp"] < CACHE_TTL:
        return entry["vulns"]
    del cache[key]
    return None


def _cache_put(cache: dict, name: str, version: str, vulns: list) -> None:
    cache[_cache_key(name, version)] = {"timestamp": time.time(), "vulns": vulns}


# ---------------------------------------------------------------------------
# 步骤 1：解析 package.json
# ---------------------------------------------------------------------------
def load_package_json(project_path: Path) -> dict:
    pkg_file = project_path / "package.json"
    if not pkg_file.exists():
        print(f"[!] 未找到 {pkg_file}，将自动创建示例文件")
        return _create_sample(project_path)
    with open(pkg_file, "r", encoding="utf-8") as f:
        return json.load(f)


def _create_sample(project_path: Path) -> dict:
    sample = {
        "name": "sample-project",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.18.0",
            "lodash": "~4.17.21",
            "axios": "1.6.0",
            "qs": "6.5.2",
        },
    }
    pkg_file = project_path / "package.json"
    with open(pkg_file, "w", encoding="utf-8") as f:
        json.dump(sample, f, indent=2)
    print(f"[+] 已创建示例 {pkg_file}")
    return sample


def extract_dependencies(pkg: dict) -> dict[str, str]:
    """从 package.json 中提取 dependencies + devDependencies 合并后返回。"""
    deps: dict[str, str] = {}
    for section in ("dependencies", "devDependencies"):
        for name, version in pkg.get(section, {}).items():
            deps[name] = version.strip().lstrip("^~>=<")
    return deps


# ---------------------------------------------------------------------------
# 步骤 2：查询 OSV API
# ---------------------------------------------------------------------------
def query_osv(session: requests.Session, name: str, version: str) -> Optional[dict]:
    payload = {
        "package": {"name": name, "ecosystem": "npm"},
        "version": version,
    }
    try:
        resp = session.post(OSV_QUERY_URL, json=payload, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 404:
            return None  # 未找到任何漏洞
        print(f"  [WARN] OSV 返回 {resp.status_code} ({name}@{version}): {resp.text[:200]}")
        return None
    except requests.RequestException as exc:
        print(f"  [ERROR] 请求失败 ({name}@{version}): {exc}")
        return None


def scan_dependencies(session: requests.Session, deps: dict[str, str], cache: dict) -> tuple[list[dict], dict]:
    """逐包查询 OSV，优先读缓存。返回 (结果列表, 更新后的缓存)。"""
    results: list[dict] = []
    total = len(deps)
    cache_hits = 0
    api_calls = 0

    for idx, (name, version) in enumerate(deps.items(), 1):
        print(f"  [{idx}/{total}] 检查 {name}@{version} ...", end=" ")

        # 尝试缓存
        cached = _cache_get(cache, name, version)
        if cached is not None:
            vulns = cached
            cache_hits += 1
            tag = "[CACHE HIT]"
        else:
            # 缓存未命中或过期 → 调 API
            data = query_osv(session, name, version)
            vulns = data.get("vulns", []) if data else []
            _cache_put(cache, name, version, vulns)
            api_calls += 1
            tag = "[API CALL]"

        if vulns:
            print(f"发现 {len(vulns)} 个漏洞  {tag}")
        else:
            print(f"安全  {tag}")
        results.append({"name": name, "version": version, "vulns": vulns})

        if idx < total:
            time.sleep(0.15)

    print(f"\n[*] 缓存命中 {cache_hits} 次，API 调用 {api_calls} 次")
    return results, cache


# ---------------------------------------------------------------------------
# 步骤 3：输出
# ---------------------------------------------------------------------------
def print_summary(results: list[dict]) -> None:
    total_vulns = sum(len(r["vulns"]) for r in results)
    affected = [r for r in results if r["vulns"]]
    print("\n" + "=" * 60)
    print(f"  扫描完成 —— 共 {len(results)} 个包，{len(affected)} 个受影响，漏洞总数 {total_vulns}")
    print("=" * 60)
    if not affected:
        print("  [OK] 未发现已知漏洞\n")
        return
    for r in affected:
        print(f"\n[PACKAGE] {r['name']}@{r['version']}")
        for v in r["vulns"]:
            cve = v.get("id", "N/A")
            aliases = ", ".join(v.get("aliases", [])) or "-"
            summary = v.get("summary", "无描述")
            severity = _pick_severity(v)
            print(f"  [VULN] {cve}  [{severity}]  {summary}")
            if aliases:
                print(f"     别名: {aliases}")
    print()


def _pick_severity(vuln: dict) -> str:
    """从 OSV 返回的 severity / database_specific 字段提取严重等级。"""
    sev = vuln.get("severity")
    if sev:
        for s in sev:
            score = s.get("score")
            if score is not None:
                return f"CVSS {score}"
    db = vuln.get("database_specific", {}) or {}
    sev_str = db.get("severity")
    if sev_str:
        return sev_str
    cvss = vuln.get("cvss", {}) or {}
    score = cvss.get("score")
    if score is not None:
        return f"CVSS {score}"
    return "UNKNOWN"


def generate_html(results: list[dict], output_path: Path) -> None:
    rows = ""
    for r in results:
        for v in r["vulns"]:
            cve = v.get("id", "N/A")
            url = _cve_url(cve)
            aliases = ", ".join(v.get("aliases", [])) or "-"
            summary = v.get("summary", "无描述") or "无描述"
            severity = _pick_severity(v)
            rows += f"""<tr>
      <td><code>{r['name']}</code></td>
      <td>{r['version']}</td>
      <td><a href="{url}" target="_blank">{cve}</a></td>
      <td>{aliases}</td>
      <td>{severity}</td>
      <td>{summary}</td>
    </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>供应链漏洞报告</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 2rem; background: #f5f5f5; color: #1a1a1a; }}
  h1 {{ color: #d32f2f; }}
  table {{ border-collapse: collapse; width: 100%; background: white; box-shadow: 0 2px 8px rgba(0,0,0,.08); }}
  th, td {{ padding: .75rem 1rem; text-align: left; border-bottom: 1px solid #e0e0e0; }}
  th {{ background: #fafafa; font-weight: 600; }}
  tr:hover {{ background: #fff3f3; }}
  code {{ background: #eee; padding: 2px 6px; border-radius: 4px; font-size: 90%; }}
  .meta {{ color: #666; font-size: 90%; margin-bottom: 1.5rem; }}
  .summary {{ background: white; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; box-shadow: 0 2px 8px rgba(0,0,0,.08); }}
</style>
</head>
<body>
<h1>供应链漏洞扫描报告</h1>
<div class="meta">
  扫描时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
  扫描包数: {len(results)}<br>
  漏洞总数: {sum(len(r['vulns']) for r in results)}
</div>
<div class="summary">
  <strong>受影响包:</strong> {len([r for r in results if r['vulns']])} / {len(results)}
</div>
<table>
<thead>
  <tr><th>包名</th><th>版本</th><th>漏洞 ID</th><th>别名</th><th>严重等级</th><th>摘要</th></tr>
</thead>
<tbody>
  {rows if rows else '<tr><td colspan="6" style="text-align:center;color:#999;">OK 未发现已知漏洞</td></tr>'}
</tbody>
</table>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] 报告已生成: {output_path.resolve()}")


def _cve_url(vuln_id: str) -> str:
    if vuln_id.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    if vuln_id.startswith("GHSA-"):
        return f"https://github.com/advisories/{vuln_id}"
    return f"https://osv.dev/vulnerability/{vuln_id}"


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
def main() -> None:
    # Windows 终端兼容：强制 stdout 使用 UTF-8
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]

    parser = argparse.ArgumentParser(description="供应链漏洞扫描器 (OSV API)")
    parser.add_argument("--path", default=".", help="项目路径 (默认当前目录)")
    parser.add_argument("--output", default="report.html", help="HTML 报告路径 (默认 report.html)")
    args = parser.parse_args()

    project_path = Path(args.path).resolve()
    print(f"[*] 项目路径: {project_path}")

    # 1. 加载 package.json
    pkg = load_package_json(project_path)

    # 2. 提取依赖
    deps = extract_dependencies(pkg)
    if not deps:
        print("[!] 未找到任何 dependencies/devDependencies")
        sys.exit(0)
    print(f"[*] 共发现 {len(deps)} 个依赖包\n")

    # 3. 扫描
    session = build_session()
    cache = _load_cache()
    print(f"[*] 缓存条目: {len(cache)}，有效期: {CACHE_TTL // 60} 分钟")
    print("[*] 开始扫描 (OSV API) ...")
    results, cache = scan_dependencies(session, deps, cache)
    _save_cache(cache)

    # 4. 输出
    print_summary(results)
    output_path = Path(args.output).resolve()
    generate_html(results, output_path)


if __name__ == "__main__":
    main()
