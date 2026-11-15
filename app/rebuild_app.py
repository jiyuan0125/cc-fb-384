#!/usr/bin/env python3
"""从 svccalls.log 重建服务调用关系，写入 SQLite 库 svcedges.db。

日志一行一条，方括号字段依次为：时间 主叫方 被叫方 链路号 事件。
事件取值 call / ok / error / retry；同一链路号的行属于同一次调用意图：
  call (error retry)* [ok|error]
链路可能中途断开（断在 call 之后或某次 retry 之后），此时没有收尾事件。

产物（均在一个 SQLite 库内，重跑结果不变）：
  边表(主叫方, 被叫方, 调用次数, 成功次数, 失败次数, 重试次数)
  未闭合登记(链路号, 时间, 主叫方, 被叫方)
  未知服务登记(链路号, 时间, 主叫方, 被叫方)
  小时汇总(小时, 调用量)          -- 小时形如 2026-05-12T10，按 call 起始小时归属
"""

from __future__ import annotations

import argparse
import os
import re
import sqlite3
import sys

# 登记在册的八个服务
KNOWN_SERVICES = frozenset({
    "edge-gateway",
    "auth-center",
    "member-profile",
    "order-broker",
    "billing-ledger",
    "stock-view",
    "push-notify",
    "search-index",
})

ALL_EVENTS = frozenset({"call", "ok", "error", "retry"})

# [时间] [主叫方] [被叫方] [链路号] [事件]
LINE_RE = re.compile(
    r"^\[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\]\s*$"
)


def parse_log(log_path):
    """按链路号聚合日志。

    返回 dict: 链路号 -> dict(caller, callee, start_time, retries, last_event)
    - retries: 该链路上 retry 事件次数
    - last_event: 链路最后一个事件；为 ok/error 表示已收尾，
      为 call/retry 表示链路中途断开（未闭合）
    同一链路的主叫/被叫在数据中保持一致，以 call 行为准并做一致性校验。
    """
    links = {}

    with open(log_path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line:
                continue
            m = LINE_RE.match(line)
            if m is None:
                raise ValueError(f"第 {lineno} 行无法解析: {line!r}")
            ts, caller, callee, link_id, event = m.groups()
            if event not in ALL_EVENTS:
                raise ValueError(f"第 {lineno} 行事件未知 {event!r}: {line!r}")

            link = links.get(link_id)
            if link is None:
                if event != "call":
                    raise ValueError(
                        f"第 {lineno} 行链路 {link_id} 首个事件不是 call: {event!r}"
                    )
                links[link_id] = {
                    "caller": caller,
                    "callee": callee,
                    "start_time": ts,
                    "retries": 0,
                    "last_event": "call",
                }
                continue

            if caller != link["caller"] or callee != link["callee"]:
                raise ValueError(
                    f"第 {lineno} 行链路 {link_id} 的主叫/被叫与 call 行不一致"
                )

            prev = link["last_event"]
            if event == "retry":
                # 一次尝试失败后才能重试：retry 必须紧跟在 error 之后
                if prev != "error":
                    raise ValueError(
                        f"第 {lineno} 行链路 {link_id} 的 retry 前序事件是 {prev!r}，应为 error"
                    )
                link["retries"] += 1
            elif event == "error":
                # error 分两种：后接 retry 时只是单次尝试失败；
                # 落在链路末尾（prev 为 call 或 retry）时才是真正的失败收尾。
                # 此处只校验转移合法性，是否收尾由最终事件统一判定。
                if prev not in ("call", "retry"):
                    raise ValueError(
                        f"第 {lineno} 行链路 {link_id} 的 error 前序事件异常: {prev!r}"
                    )
            elif event == "ok":
                # ok 只可能是收尾，前序必须是 call 或 retry
                if prev not in ("call", "retry"):
                    raise ValueError(
                        f"第 {lineno} 行链路 {link_id} 的 ok 前序事件异常: {prev!r}"
                    )
            else:
                # 同一链路出现第二个 call
                raise ValueError(
                    f"第 {lineno} 行链路 {link_id} 在 call 之后又出现 call 事件"
                )
            link["last_event"] = event

    return links


def build(links):
    """把聚合后的链路整理成四张表所需的行。"""
    # 边表: (主叫, 被叫) -> [调用, 成功, 失败, 重试]
    edges = {}
    unclosed_rows = []   # (链路号, 时间, 主叫, 被叫)
    unknown_rows = []    # (链路号, 时间, 主叫, 被叫)
    hourly = {}          # 小时 -> 调用量

    for link_id, link in links.items():
        caller = link["caller"]
        callee = link["callee"]
        start_time = link["start_time"]
        hour = start_time[:13]  # 2026-05-12T10

        edge = edges.setdefault((caller, callee), [0, 0, 0, 0])
        edge[0] += 1                      # 调用次数：一次链路意图算一次调用
        edge[3] += link["retries"]        # 重试次数
        last_event = link["last_event"]
        if last_event == "ok":
            edge[1] += 1                  # 成功次数
        elif last_event == "error":
            edge[2] += 1                  # 失败次数
        else:
            # 末事件是 call 或 retry：没有等到 ok/error 收尾，链路中途断开
            unclosed_rows.append((link_id, start_time, caller, callee))

        if caller not in KNOWN_SERVICES or callee not in KNOWN_SERVICES:
            unknown_rows.append((link_id, start_time, caller, callee))

        hourly[hour] = hourly.get(hour, 0) + 1

    edge_rows = [
        (caller, callee, calls, succ, fail, retries)
        for (caller, callee), (calls, succ, fail, retries) in sorted(edges.items())
    ]
    unclosed_rows.sort(key=lambda r: r[1])   # 按 call 时间排序，结果稳定
    unknown_rows.sort(key=lambda r: r[1])
    hourly_rows = sorted(hourly.items())
    return edge_rows, unclosed_rows, unknown_rows, hourly_rows


def write_db(db_path, edge_rows, unclosed_rows, unknown_rows, hourly_rows):
    """整库重建：先删旧表再写入，保证重跑幂等。"""
    if os.path.exists(db_path):
        os.remove(db_path)

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "CREATE TABLE 边表 ("
            "主叫方 TEXT NOT NULL, 被叫方 TEXT NOT NULL, "
            "调用次数 INTEGER NOT NULL, 成功次数 INTEGER NOT NULL, "
            "失败次数 INTEGER NOT NULL, 重试次数 INTEGER NOT NULL)"
        )
        cur.execute(
            "CREATE TABLE 未闭合登记 ("
            "链路号 TEXT NOT NULL, 时间 TEXT NOT NULL, "
            "主叫方 TEXT NOT NULL, 被叫方 TEXT NOT NULL)"
        )
        cur.execute(
            "CREATE TABLE 未知服务登记 ("
            "链路号 TEXT NOT NULL, 时间 TEXT NOT NULL, "
            "主叫方 TEXT NOT NULL, 被叫方 TEXT NOT NULL)"
        )
        cur.execute(
            "CREATE TABLE 小时汇总 (小时 TEXT NOT NULL, 调用量 INTEGER NOT NULL)"
        )

        cur.executemany(
            "INSERT INTO 边表 VALUES (?, ?, ?, ?, ?, ?)", edge_rows
        )
        cur.executemany(
            "INSERT INTO 未闭合登记 VALUES (?, ?, ?, ?)", unclosed_rows
        )
        cur.executemany(
            "INSERT INTO 未知服务登记 VALUES (?, ?, ?, ?)", unknown_rows
        )
        cur.executemany(
            "INSERT INTO 小时汇总 VALUES (?, ?)", hourly_rows
        )
        conn.commit()
    finally:
        conn.close()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="从 svccalls.log 重建服务调用关系到 svcedges.db"
    )
    parser.add_argument(
        "--log", default="svccalls.log", help="原始日志路径（默认 svccalls.log）"
    )
    parser.add_argument(
        "--db", default="svcedges.db", help="输出 SQLite 库路径（默认 svcedges.db）"
    )
    args = parser.parse_args(argv)

    links = parse_log(args.log)
    edge_rows, unclosed_rows, unknown_rows, hourly_rows = build(links)
    write_db(args.db, edge_rows, unclosed_rows, unknown_rows, hourly_rows)

    total_calls = sum(r[2] for r in edge_rows)
    total_succ = sum(r[3] for r in edge_rows)
    total_fail = sum(r[4] for r in edge_rows)
    total_retry = sum(r[5] for r in edge_rows)
    print(
        f"链路 {len(links)} 条；边 {len(edge_rows)} 条；"
        f"调用 {total_calls}（成功 {total_succ}/失败 {total_fail}），"
        f"重试 {total_retry}；未闭合 {len(unclosed_rows)}；"
        f"未知服务 {len(unknown_rows)}；小时桶 {len(hourly_rows)}"
    )


if __name__ == "__main__":
    sys.exit(main())
