#!/usr/bin/env python3
"""
日志安全审计脚本 —— 分析安全日志，检测暴力破解和异常时间段登录行为。
纯标准库实现，无第三方依赖，可直接运行。
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Tuple

# ---------------------------------------------------------------------------
# 日志行正则匹配
# 格式示例: [2026-05-16 03:25:10] Failed password for admin from 192.168.1.100
# 支持 "Failed password for X from IP" 和 "Accepted password for X from IP"
# 以及 "Failed password for invalid user X from IP"
# ---------------------------------------------------------------------------
LOG_PATTERN = re.compile(
    r"\[(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+"
    r"(?P<action>Failed|Accepted)\s+password\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)

# 异常阈值
BRUTE_FORCE_THRESHOLD = 5      # 同一IP在窗口内失败次数
BRUTE_FORCE_WINDOW_MIN = 10    # 滑动窗口大小（分钟）
OFF_HOURS_START = 0            # 异常时间段起始小时
OFF_HOURS_END = 6              # 异常时间段结束小时（不含）


# ---------------------------------------------------------------------------
# 工具：Windows 控制台编码兼容
# ---------------------------------------------------------------------------
def setup_console_encoding() -> None:
    """确保 Windows 终端正常输出中文，无效果则静默跳过。"""
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 测试日志生成
# ---------------------------------------------------------------------------
def generate_test_log() -> str:
    """
    生成包含已知异常模式的测试日志内容。
    返回多行字符串，每行为一条日志记录。
    覆盖场景：
      - 正常登录
      - 同一IP连续暴力破解（≥5次/10分钟）
      - 凌晨异常时段登录
      - 边界情况（恰好5次、跨窗口）
    """
    lines: list[str] = []

    def add(ts: str, action: str, user: str, ip: str) -> None:
        lines.append(f"[{ts}] {action} password for {user} from {ip}")

    # --- 正常登录（不应触发告警）---
    add("2026-05-16 09:15:01", "Accepted", "admin",    "10.0.0.1")
    add("2026-05-16 09:16:10", "Failed",   "admin",    "10.0.0.1")  # 仅1次失败
    add("2026-05-16 09:17:20", "Accepted", "root",     "10.0.0.2")
    add("2026-05-16 10:00:00", "Failed",   "admin",    "10.0.0.1")  # 距离上一失败 >10分钟

    # --- 暴力破解场景 A：192.168.1.100 在 3 分钟内失败 6 次 ---
    base = datetime(2026, 5, 16, 3, 20, 0)
    for i in range(7):
        t = base + timedelta(seconds=i * 30)
        add(t.strftime("%Y-%m-%d %H:%M:%S"), "Failed", "admin", "192.168.1.100")

    # --- 暴力破解场景 B：10.10.10.50 正好失败 5 次 ---
    base = datetime(2026, 5, 16, 14, 5, 0)
    for i in range(5):
        t = base + timedelta(seconds=i * 90)
        add(t.strftime("%Y-%m-%d %H:%M:%S"), "Failed", "root", "10.10.10.50")

    # --- 凌晨异常登录（00:00-06:00）---
    add("2026-05-16 02:10:00", "Accepted", "admin",   "172.16.0.1")
    add("2026-05-16 02:10:30", "Failed",   "admin",   "172.16.0.1")  # 仅1次失败，不够暴力破解
    add("2026-05-16 05:59:59", "Accepted", "operator","172.16.0.2")

    # --- 正常时间的成功登录 ---
    add("2026-05-16 08:30:00", "Accepted", "admin",   "10.0.0.1")
    add("2026-05-16 12:00:00", "Accepted", "root",    "10.0.0.2")
    add("2026-05-16 18:45:00", "Failed",   "guest",   "10.0.0.3")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# 日志解析
# ---------------------------------------------------------------------------
def parse_log_lines(lines: list[str]) -> list[dict]:
    """
    逐行解析日志，返回结构化记录列表。
    格式不匹配的行将被跳过（打印警告，不计入解析）。
    """
    records: list[dict] = []
    for lineno, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line:
            continue
        m = LOG_PATTERN.search(line)
        if not m:
            print(f"  [WARN] 第 {lineno} 行格式不匹配: {line[:80]}")
            continue
        try:
            ts = datetime.strptime(m.group("timestamp"), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            print(f"  [WARN] 第 {lineno} 行时间解析失败: {line[:80]}")
            continue
        records.append({
            "timestamp": ts,
            "raw": line,
            "user": m.group("user"),
            "ip": m.group("ip"),
            "action": m.group("action"),  # "Failed" 或 "Accepted"
        })
    return records


# ---------------------------------------------------------------------------
# 异常检测
# ---------------------------------------------------------------------------
def detect_off_hours(records: list[dict]) -> list[dict]:
    """
    检测时间戳落在 00:00–06:00 之间的登录记录。
    返回异常记录列表（含异常类型标记）。
    """
    anomalies: list[dict] = []
    for r in records:
        hour = r["timestamp"].hour
        if OFF_HOURS_START <= hour < OFF_HOURS_END:
            anomalies.append({
                "type": "off_hours_login",
                "timestamp": r["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                "user": r["user"],
                "ip": r["ip"],
                "action": r["action"],
                "raw": r["raw"],
                "detail": f"登录时间 {r['timestamp'].strftime('%H:%M')} 处于异常时段 ({OFF_HOURS_START:02d}:00–{OFF_HOURS_END:02d}:00)",
            })
    return anomalies


def detect_brute_force(records: list[dict]) -> list[dict]:
    """
    使用滑动窗口检测暴力破解：
    对于每个 IP，将失败记录按时间排序，用 10 分钟窗口检查是否有 ≥5 次失败。
    重叠窗口自动合并为一条告警，记录批次内失败总数及起止时间。
    """
    ip_failures: dict[str, list[datetime]] = defaultdict(list)
    for r in records:
        if r["action"] == "Failed":
            ip_failures[r["ip"]].append(r["timestamp"])

    anomalies: list[dict] = []
    window = timedelta(minutes=BRUTE_FORCE_WINDOW_MIN)

    for ip, timestamps in ip_failures.items():
        timestamps.sort()

        # 第一步：收集所有满足阈值条件的窗口 [left_idx, right_idx]
        bad_windows: list[tuple[int, int]] = []
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > window:
                left += 1
            if right - left + 1 >= BRUTE_FORCE_THRESHOLD:
                bad_windows.append((left, right))

        if not bad_windows:
            continue

        # 第二步：合并重叠窗口，输出合并后的批次
        merged_start, merged_end = bad_windows[0]
        for ws, we in bad_windows[1:]:
            if ws <= merged_end:  # 重叠或相邻 → 合并
                merged_end = max(merged_end, we)
            else:  # 断档 → 提交当前批次，开启新批次
                count = merged_end - merged_start + 1
                anomalies.append(_make_bf_entry(ip, count, timestamps[merged_start], timestamps[merged_end]))
                merged_start, merged_end = ws, we
        # 提交最后一个批次
        count = merged_end - merged_start + 1
        anomalies.append(_make_bf_entry(ip, count, timestamps[merged_start], timestamps[merged_end]))

    return anomalies


def _make_bf_entry(ip: str, count: int, first_ts: datetime, last_ts: datetime) -> dict:
    """构建一条暴力破解异常记录。"""
    return {
        "type": "brute_force",
        "ip": ip,
        "count": count,
        "first_attempt": first_ts.strftime("%Y-%m-%d %H:%M:%S"),
        "last_attempt": last_ts.strftime("%Y-%m-%d %H:%M:%S"),
        "detail": (
            f"IP {ip} 在 {BRUTE_FORCE_WINDOW_MIN} 分钟内 "
            f"失败登录 {count} 次（阈值 {BRUTE_FORCE_THRESHOLD} 次）"
        ),
    }


# ---------------------------------------------------------------------------
# 白名单
# ---------------------------------------------------------------------------
def load_whitelist(path: str | None) -> set[str]:
    """从文件加载白名单，每行一个 IP 或用户名，空行和 # 注释行自动跳过。"""
    if not path:
        return set()
    whitelist_path = Path(path)
    if not whitelist_path.exists():
        print(f"[WARN] 白名单文件不存在，忽略: {whitelist_path.resolve()}")
        return set()
    entries: set[str] = set()
    with open(whitelist_path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            entries.add(stripped)
    print(f"[*] 已加载白名单: {len(entries)} 条 ({whitelist_path.resolve()})")
    return entries


def apply_whitelist(anomalies: list[dict], whitelist: set[str]) -> tuple[list[dict], int]:
    """
    过滤异常列表：若记录的 ip 或 user 字段出现在白名单中，则移除。
    返回 (过滤后列表, 被过滤的数量)。
    """
    if not whitelist:
        return anomalies, 0
    filtered: list[dict] = []
    skipped = 0
    for a in anomalies:
        ip = a.get("ip", "")
        user = a.get("user", "")
        if ip in whitelist or user in whitelist:
            skipped += 1
            continue
        filtered.append(a)
    return filtered, skipped


# ---------------------------------------------------------------------------
# 报告输出
# ---------------------------------------------------------------------------
def output_report(
    anomalies: list[dict],
    total_records: int,
    file_path: str,
    output_path: str | None,
) -> str:
    """
    构建 JSON 报告，可选写入文件。返回 JSON 字符串。
    """
    anomaly_types: dict[str, list[dict]] = defaultdict(list)
    for a in anomalies:
        anomaly_types[a["type"]].append(a)

    report = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_file": os.path.abspath(file_path),
        "summary": {
            "total_records": total_records,
            "total_anomalies": len(anomalies),
            "off_hours_count": len(anomaly_types.get("off_hours_login", [])),
            "brute_force_count": len(anomaly_types.get("brute_force", [])),
        },
        "anomalies": anomalies,
    }

    json_str = json.dumps(report, ensure_ascii=False, indent=2)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
        print(f"\n[+] JSON 报告已写入: {os.path.abspath(output_path)}")

    return json_str


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
def main() -> None:
    setup_console_encoding()

    parser = argparse.ArgumentParser(
        description="日志安全审计工具 —— 检测暴力破解与异常时间段登录"
    )
    parser.add_argument(
        "--file",
        default="security.log",
        help="指定日志文件路径（默认 security.log）",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="生成测试日志并分析，忽略 --file 参数",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="将 JSON 报告写入指定文件（可选）",
    )
    parser.add_argument(
        "--whitelist",
        default=None,
        help="白名单文件路径，每行一个 IP 或用户名（# 开头为注释）",
    )
    args = parser.parse_args()

    # --- 1. 获取日志数据 ---
    if args.test:
        print("[*] 测试模式：生成示例日志数据\n")
        log_text = generate_test_log()
        source = "(test data)"
    else:
        log_path = Path(args.file)
        if not log_path.exists():
            print(f"[ERROR] 文件不存在: {log_path.resolve()}")
            print("[TIP] 使用 --test 生成测试数据，或检查路径是否正确")
            sys.exit(1)
        try:
            log_text = log_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            # 回退：尝试系统默认编码
            log_text = log_path.read_text(encoding="gbk", errors="replace")
        source = str(log_path.resolve())
        print(f"[*] 读取日志文件: {source}\n")

    # --- 2. 解析 ---
    raw_lines = log_text.splitlines()
    records = parse_log_lines(raw_lines)
    print(f"[*] 成功解析 {len(records)} 条日志记录（共 {len(raw_lines)} 行）")

    if not records:
        print("[!] 无可解析的有效日志，退出")
        # 仍输出空报告
        report_json = output_report([], 0, source, args.output)
        print(report_json)
        return

    # --- 3. 加载白名单 ---
    whitelist = load_whitelist(args.whitelist)

    # --- 4. 检测异常 ---
    all_anomalies: list[dict] = []
    all_anomalies.extend(detect_off_hours(records))
    all_anomalies.extend(detect_brute_force(records))
    raw_count = len(all_anomalies)

    # --- 5. 应用白名单过滤 ---
    all_anomalies, filtered_count = apply_whitelist(all_anomalies, whitelist)
    if filtered_count > 0:
        print(f"[*] 白名单过滤: 排除 {filtered_count} 条异常（剩余 {len(all_anomalies)} 条）")

    # --- 6. 输出报告 ---
    report_json = output_report(all_anomalies, len(records), source, args.output)
    print(report_json)

    # --- 7. 简要摘要 ---
    if all_anomalies:
        print(f"\n[!] 发现 {len(all_anomalies)} 个异常事件（原始 {raw_count} 个，过滤 {filtered_count} 个）")
    else:
        if raw_count > 0:
            print(f"\n[OK] {raw_count} 个异常全部被白名单排除，最终报告无异常")
        else:
            print("\n[OK] 未发现异常事件")


if __name__ == "__main__":
    main()
