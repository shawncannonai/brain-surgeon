#!/usr/bin/env python3
"""Which kills are futile? Processes the surgeon keeps killing that keep coming back.

WHY THIS EXISTS. 2026-09-26: Loom.exe was killed at 13:03, 13:05 and 13:10, a
different PID each time, recovering under 200 MB in total. The surgeon had no way to
notice. Every rule it has answers "is this worth killing now", and none of them ask
"have I killed this nine times already".

A repeat kill is worse than no kill. It frees nothing durable, it costs a kill every
cycle forever, and it means an app the operator is using dies under him with no explanation
at a moment he cannot predict. The real fix for a respawner is its autostart, not its
process, and that fix has to be made by a human once rather than by the surgeon every
five minutes.

    python churn.py                 last 24h
    python churn.py --hours 168     last week
    python churn.py --min 3         only names killed 3+ times
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

ACTIONS = Path(__file__).resolve().parent / "state" / "actions.jsonl"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=24.0)
    ap.add_argument("--min", type=int, default=2, help="report names killed at least N times")
    a = ap.parse_args()

    if not ACTIONS.exists():
        print("no actions.jsonl yet")
        return 0

    since = datetime.now(timezone.utc) - timedelta(hours=a.hours)
    by: dict[str, list[dict]] = defaultdict(list)
    for line in ACTIONS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
            when = datetime.fromisoformat(r["at"])
        except (ValueError, KeyError):
            continue
        if when >= since:
            by[r.get("name", "?")].append(r)

    if not by:
        print(f"no kills in the last {a.hours:.0f}h")
        return 0

    rows = sorted(by.items(), key=lambda kv: -len(kv[1]))
    print(f"kills in the last {a.hours:.0f}h\n")
    print(f"{'process':<28} {'kills':>6} {'MB freed':>9} {'MB/kill':>8} {'distinct PIDs':>14}")
    churners = []
    for name, rs in rows:
        mb = sum(r.get("private_mb", 0) for r in rs)
        pids = len({r.get("pid") for r in rs})
        print(f"{name:<28} {len(rs):>6} {mb:>9} {mb / len(rs):>8.0f} {pids:>14}")
        if len(rs) >= a.min and pids == len(rs):
            churners.append((name, len(rs), mb))

    if churners:
        print("\nCHURN, and every one of these is a bug in the plan, not in the machine:")
        for name, n, mb in churners:
            print(f"  {name}: killed {n} times, {n} different PIDs, {mb} MB total.")
            print(f"    It respawns. Killing it again next cycle will free {mb // n} MB")
            print(f"    for about two minutes. Disable its autostart instead.")
        print("\n  Task Manager > Startup apps, or remove it from HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    else:
        print(f"\nNo churn: nothing was killed {a.min}+ times with a fresh PID each time.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
