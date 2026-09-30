#!/usr/bin/env python3
"""Brain Surgeon: keep the machine's memory for the work that is running, by removing what is not.

    python brain_surgeon.py                 # dry run: pressure, and what each rule WOULD kill
    python brain_surgeon.py --apply         # kill what the rules name, log it, alert on Telegram
    python brain_surgeon.py --json          # machine-readable report

The operator, 2026-09-17: "we need a brain surgeon monitor that will routinely kill processes unnecessary to any tasks that
are currently running so nothing gets shut down, we eventually will be needing to resolve this by just moving
everything possibly to a cloud."

WHY. At 21:35 EDT on 2026-09-16 one Chrome tab (a web inbox, in a scraper-automation profile) reached 15 GB
private memory. Commit charge hit 57.6 of 58.9 GB, n8n stopped answering, and a phone agent's tools and bookings failed
for ten hours. The n8n healthcheck then launched a PowerShell every five minutes that could never finish: 59 of them.
Nothing that ran saw the machine as a whole, so nothing noticed. This does.

HOW IT DECIDES. Pressure first (commit charge and free physical memory, read from Windows itself), then four named
rules in policy.json. A process dies only when a rule names it; size alone is never a reason, and anything on the
protected list (Claude sessions, the tunnel, n8n, the booking API, trading apps, monitors, browsers' main processes
on their debugging ports, and every ancestor of those) is untouched at any pressure. Chrome is always cut at the
renderer, one tab, never the browser: the tab shows "Aw, Snap" and reloads, the logins and other tabs stay.

SAFETY. Dry run unless --apply. Single instance (a second copy exits). Hard time limit. Every kill is written to
state/actions.jsonl with the rule, pressure, memory and a redacted command line. It never restarts anything; after
acting it reports whether n8n answers, because an elevated n8n cannot be restarted from here.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import sys
import time
import urllib.request
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path

import psutil

HERE = Path(__file__).resolve().parent
POLICY = json.loads((HERE / "policy.json").read_text(encoding="utf-8"))
STATE = HERE / "state"
ACTIONS = STATE / "actions.jsonl"
LAST = STATE / "last.json"
DEADLINE_S = 90
HEALTH_URL = POLICY.get("health_url", "http://localhost:8800/healthz")

SECRETISH = re.compile(r"([A-Za-z0-9_\-]{28,}|token=[^&\s\"]+|key=[^&\s\"]+)")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def redact(cmd: str, limit: int = 220) -> str:
    return SECRETISH.sub("<redacted>", cmd or "")[:limit]


# -- pressure ------------------------------------------------------------------------------------------------------

class PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("CommitTotal", ctypes.c_size_t), ("CommitLimit", ctypes.c_size_t),
                ("CommitPeak", ctypes.c_size_t), ("PhysicalTotal", ctypes.c_size_t),
                ("PhysicalAvailable", ctypes.c_size_t), ("SystemCache", ctypes.c_size_t),
                ("KernelTotal", ctypes.c_size_t), ("KernelPaged", ctypes.c_size_t),
                ("KernelNonpaged", ctypes.c_size_t), ("PageSize", ctypes.c_size_t),
                ("HandleCount", wintypes.DWORD), ("ProcessCount", wintypes.DWORD), ("ThreadCount", wintypes.DWORD)]


def pressure() -> dict:
    pi = PERFORMANCE_INFORMATION()
    pi.cb = ctypes.sizeof(pi)
    ctypes.windll.psapi.GetPerformanceInfo(ctypes.byref(pi), pi.cb)
    mb = pi.PageSize / (1024 * 1024)
    commit, limit, free = pi.CommitTotal * mb, pi.CommitLimit * mb, pi.PhysicalAvailable * mb
    pct = 100.0 * commit / limit if limit else 0.0
    p = POLICY["pressure"]
    level = "GREEN"
    if pct >= p["amber_commit_pct"] or free < p["amber_free_mb"]:
        level = "AMBER"
    if pct >= p["red_commit_pct"] or free < p["red_free_mb"]:
        level = "RED"
    return {"level": level, "commit_mb": round(commit), "commit_limit_mb": round(limit),
            "commit_pct": round(pct, 1), "free_mb": round(free)}


# -- inventory -----------------------------------------------------------------------------------------------------

def snapshot() -> list[dict]:
    rows = []
    for p in psutil.process_iter(["pid", "ppid", "name", "create_time"]):
        info = p.info
        try:
            cmd = " ".join(p.cmdline())
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            cmd = ""
        try:
            private = p.memory_full_info().private / (1024 * 1024) if hasattr(p, "memory_full_info") else 0
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            try:
                private = p.memory_info().private / (1024 * 1024)
            except Exception:                                   # noqa: BLE001
                private = 0
        rows.append({"pid": info["pid"], "ppid": info["ppid"], "name": info["name"] or "",
                     "age_min": (time.time() - (info["create_time"] or time.time())) / 60,
                     "cmd": cmd, "private_mb": round(private)})
    return rows


def protected_pids(rows: list[dict]) -> set[int]:
    prot = POLICY["protected"]
    names = {n.lower() for n in prot["names"]}
    by_pid = {r["pid"]: r for r in rows}
    keep = {os.getpid(), os.getppid()}
    for r in rows:
        low = r["cmd"].lower()
        if r["name"].lower() in names or any(s.lower() in low for s in prot["cmdline_contains"]):
            keep.add(r["pid"])
    try:
        for c in psutil.net_connections(kind="tcp"):
            if c.status == psutil.CONN_LISTEN and c.laddr and c.laddr.port in prot["listening_ports"] and c.pid:
                keep.add(c.pid)
    except (psutil.AccessDenied, OSError):
        pass
    # Ancestors of anything protected are protected too: killing the cmd.exe that runs n8n kills n8n.
    for pid in list(keep):
        cur, hops = by_pid.get(pid), 0
        while cur and hops < 4:
            keep.add(cur["pid"])
            cur, hops = by_pid.get(cur["ppid"]), hops + 1
    return keep


# -- rules ---------------------------------------------------------------------------------------------------------

def profile_of(cmd: str) -> str:
    m = re.search(r'--user-data-dir="?([^"]+?)"?(\s--|$)', cmd)
    return m.group(1) if m else ""


def candidates(rows: list[dict], level: str, keep: set[int]) -> list[dict]:
    rules, out = POLICY["rules"], []
    order = {"GREEN": 0, "AMBER": 1, "RED": 2}[level]
    live = [r for r in rows if r["pid"] not in keep]

    # 1. stuck duplicate scheduled scripts
    rule = rules["stuck_duplicate_script"]
    interps = {n.lower() for n in rule["interpreters"]}
    groups: dict[str, list[dict]] = {}
    for r in live:
        if r["name"].lower() in interps and any(s.lower() in r["cmd"].lower() for s in rule["cmdline_must_contain_any"]):
            groups.setdefault(re.sub(r"\s+", " ", r["cmd"]).strip().lower(), []).append(r)
    for cmd, members in groups.items():
        if len(members) < rule["min_copies"]:
            continue
        members.sort(key=lambda r: r["age_min"])
        if members[-1]["age_min"] < rule["oldest_min_age_minutes"]:
            continue
        for r in members[1:]:                                   # keep the newest copy
            out.append({**r, "rule": "stuck_duplicate_script",
                        "why": f"{len(members)} identical copies, oldest {members[-1]['age_min']:.0f} min"})

    # 2 and 3. renderers
    auto = rules["bloated_automation_renderer"]
    personal = rules["bloated_personal_renderer"]
    for r in live:
        if r["name"].lower() != "chrome.exe" or "--type=renderer" not in r["cmd"]:
            continue
        prof = profile_of(r["cmd"]).lower()
        is_auto = any(s.lower() in prof or s.lower() in r["cmd"].lower() for s in auto["profiles_contain_any"])
        if is_auto:
            limit = auto["private_mb_any_pressure"] if order == 0 else auto["private_mb_amber"]
            if r["private_mb"] >= limit:
                out.append({**r, "rule": "bloated_automation_renderer",
                            "why": f"{r['private_mb']} MB tab in automation profile {prof[-40:]}"})
        elif order == 2 and r["private_mb"] >= personal["private_mb_red"]:
            out.append({**r, "rule": "bloated_personal_renderer",
                        "why": f"{r['private_mb']} MB tab in personal browser at RED pressure"})

    # 4. orphan headless
    if order >= 1:
        rule = rules["orphan_headless"]
        pids = {r["pid"] for r in rows}
        for r in live:
            if (any(s in r["cmd"] for s in rule["cmdline_contains_any"]) and r["ppid"] not in pids
                    and r["age_min"] >= rule["min_age_minutes"]):
                out.append({**r, "rule": "orphan_headless", "why": f"parent {r['ppid']} gone, {r['age_min']:.0f} min old"})

    seen, unique = set(), []
    for c in out:
        if c["pid"] not in seen:
            seen.add(c["pid"])
            unique.append(c)
    return unique


def last_resort(rows: list[dict], keep: set[int], level: str = "RED") -> list[dict]:
    """Ranked targets for when memory is still RED and no ordinary rule matched.

    AT AMBER, THE EXPENDABLE APPS ONLY. The operator, 2026-09-22, after an approved carrier
    registration could not be submitted five times because the tab kept being killed:
    *"have the brain surgeon run periodically, see how much memory we need available,
    and then it'll just cut processes that it's clear we're not using or don't need."*
    Loom, Spotify, OneDrive, Teams, the phone-link host, Widgets and the search host are
    exactly that list, and losing any of them costs nothing. Browser and webview TABS
    stay RED-only, because a tab can hold work a person has not saved and "clearly not
    needed" is not true of those.

    Whole expendable apps first (every process of that app, biggest first), then the
    largest browser or webview tabs. A killed tab shows "Aw, Snap" and reloads; the
    browser and every other tab stay. Protected processes and their ancestors are
    never in `rows - keep`, so Claude, TradingView, n8n and the tunnel cannot appear.
    """
    rule = POLICY["rules"]["last_resort"]
    live = [r for r in rows if r["pid"] not in keep]
    out = []
    for app in rule["apps"]:
        members = sorted((r for r in live if r["name"].lower() == app.lower()), key=lambda r: -r["private_mb"])
        out += [{**r, "rule": "last_resort", "why": f"expendable app {app} at {level}"} for r in members]
    if level != "RED":
        return out
    rnd = rule["renderers"]
    names = {n.lower() for n in rnd["names"]}
    tabs = [r for r in live if r["name"].lower() in names and "--type=renderer" in r["cmd"]
            and "--extension-process" not in r["cmd"] and r["private_mb"] >= rnd["min_private_mb"]]
    # A TAB AN AUTOMATION JUST OPENED IS MID-TASK. 2026-09-25 00:18 ET this rule killed a 2-minute-old 793 MB
    # vendor checkout tab in the :9222 automation Chrome while an order was being priced (21 Chrome kills
    # since 09-18, six of them another automation Chrome on 09-22, each costing a vendor re-sign-in). Young renderers
    # in a debugging-port (automation) profile are moved to the very end of the list: after every older tab,
    # tier-2 app and small tab. Still killable if nothing else frees memory, so RED can never be pinned.
    young_min = rnd.get("automation_young_minutes", 10)
    young = [r for r in tabs if "--remote-debugging-port=" in r["cmd"] and r["age_min"] < young_min]
    tabs = [r for r in tabs if r not in young]
    out += [{**r, "rule": "last_resort", "why": f"{r['private_mb']} MB tab/webview at RED"}
            for r in sorted(tabs, key=lambda r: -r["private_mb"])]
    # RED TIER 2 (Design note, 2026-09-24: "critically low on memory is no excuse ... fixing it immediately"). On a 16 GB
    # machine ~90 browser processes held 8 GB with none over 700 MB, so tier 1 found nothing and RED sat for an hour.
    # Tier 2: desktop clients whose phone app carries the same thing, then smaller Edge/webview tabs. Chrome keeps
    # its 700 MB floor because the live trading terminals are Chrome tabs and a renderer does not show its URL.
    t2 = rule.get("red_tier2") or {}
    for app in t2.get("apps", []):
        members = sorted((r for r in live if r["name"].lower() == app.lower()), key=lambda r: -r["private_mb"])
        out += [{**r, "rule": "last_resort", "why": f"tier-2 app {app} at RED"} for r in members]
    floors = {k.lower(): v for k, v in (t2.get("renderer_min_mb") or {}).items()}
    small = [r for r in live if r["name"].lower() in floors and "--type=renderer" in r["cmd"]
             and "--extension-process" not in r["cmd"] and r["private_mb"] >= floors[r["name"].lower()]
             and r not in tabs]
    out += [{**r, "rule": "last_resort", "why": f"tier-2 {r['private_mb']} MB {r['name']} tab at RED"}
            for r in sorted(small, key=lambda r: -r["private_mb"]) if r not in young]
    out += [{**r, "rule": "last_resort", "why": f"{r['private_mb']} MB automation tab, {r['age_min']:.0f} min old, "
                                                 f"killed last at RED"}
            for r in sorted(young, key=lambda r: -r["private_mb"])]
    # One entry per process. Loom sits in both `apps` and `red_tier2.apps` (09-24 tuning), which listed each
    # Loom process twice and spent two of the per-run kill slots on a pid already gone.
    seen: set[int] = set()
    return [r for r in out if not (r["pid"] in seen or seen.add(r["pid"]))]


# -- act -----------------------------------------------------------------------------------------------------------

def kill(c: dict) -> str:
    try:
        psutil.Process(c["pid"]).kill()
        return "killed"
    except psutil.NoSuchProcess:
        return "already_gone"
    except psutil.AccessDenied:
        return "access_denied"
    except Exception as e:                                      # noqa: BLE001
        return f"error: {str(e)[:60]}"


def n8n_ok() -> bool:
    try:
        with urllib.request.urlopen(HEALTH_URL, timeout=8) as r:
            return r.status == 200
    except Exception:                                           # noqa: BLE001
        return False


def alert(text: str) -> None:
    # NO TELEGRAM, not even on failure. The operator, 2026-09-17 (second time that day, after an 08:30 failure alert
    # still reached his phone): "I don't need brain surgeon alerts going to telegram". Failures are written to
    # state/alerts.log for a session or the conductor to read. Do not re-add a phone send unless he asks.
    try:
        with (STATE / "alerts.log").open("a", encoding="utf-8") as fh:
            fh.write(f"{now()} {text}\n")
    except Exception:                                           # noqa: BLE001
        pass


def already_running() -> bool:
    # A venv's python.exe/pythonw.exe is a launcher that starts the real interpreter as a CHILD with the same
    # command line, so this process's own parent looks like "another run". Found on the first scheduled run
    # (2026-09-17), which exited without acting. Exclude self and every ancestor.
    me = {os.getpid()}
    try:
        me.update(a.pid for a in psutil.Process().parents())
    except Exception:                                           # noqa: BLE001
        pass
    # IT MUST BE A PYTHON INTERPRETER, not merely a process that mentions the file.
    # 2026-09-22: every manual `--apply` bounced with "another run is in progress"
    # while nothing was running. The shell that launches it carries the whole command
    # line, filename included, and so did the sibling shells of any other command typed
    # in the same second, none of which are ancestors. So the surgeon could be run only
    # by Task Scheduler, which is exactly when a person most wants to run it by hand.
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            if p.info["pid"] in me:
                continue
            if (p.info["name"] or "").lower() not in ("python.exe", "pythonw.exe", "python"):
                continue
            if any("brain_surgeon.py" in (a or "") for a in (p.info["cmdline"] or [])):
                return True
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    started = time.time()
    STATE.mkdir(parents=True, exist_ok=True)
    if a.apply and already_running():
        print("another Brain Surgeon run is in progress; exiting")
        return 0

    before = pressure()
    rows = snapshot()
    keep = protected_pids(rows)
    cands = candidates(rows, before["level"], keep)
    results = []
    for c in cands:
        if time.time() - started > DEADLINE_S:
            break
        outcome = kill(c) if a.apply else "would_kill"
        results.append({"at": now(), "pid": c["pid"], "name": c["name"], "rule": c["rule"], "why": c["why"],
                        "private_mb": c["private_mb"], "age_min": round(c["age_min"]), "cmd": redact(c["cmd"]),
                        "outcome": outcome, "pressure": before["level"]})
    if a.apply and results:
        time.sleep(3)
    after = pressure() if (a.apply and results) else before

    # Last resort: still RED after the ordinary rules. Free one target at a time until memory is safe.
    if after["level"] in ("RED", "AMBER"):
        lr = POLICY["rules"]["last_resort"]
        done = {r["pid"] for r in results}
        for c in last_resort(rows, keep, after["level"]):
            if c["pid"] in done or time.time() - started > DEADLINE_S:
                continue
            if sum(1 for r in results if r["rule"] == "last_resort") >= lr["max_kills_per_run"]:
                break
            outcome = kill(c) if a.apply else "would_kill"
            done.add(c["pid"])
            results.append({"at": now(), "pid": c["pid"], "name": c["name"], "rule": c["rule"], "why": c["why"],
                            "private_mb": c["private_mb"], "age_min": round(c["age_min"]), "cmd": redact(c["cmd"]),
                            "outcome": outcome, "pressure": after["level"]})
            if not a.apply:
                continue
            time.sleep(2)
            after = pressure()
            if after["free_mb"] >= lr["stop_when_free_mb"]:
                break
    report = {"at": now(), "apply": a.apply, "before": before, "after": after, "protected": len(keep),
              "processes": len(rows), "actions": results}
    if a.apply:
        with ACTIONS.open("a", encoding="utf-8") as fh:
            for r in results:
                fh.write(json.dumps(r) + "\n")
        report["n8n_ok"] = n8n_ok()
        LAST.write_text(json.dumps(report, indent=1), encoding="utf-8")
        killed = [r for r in results if r["outcome"] == "killed"]
        # Telegram only when the job FAILED. The operator, 2026-09-17: "i don't need brain surgeon sending me
        # telegrams, if it's running and doing it's job i don't care." A kill that worked is the job;
        # it stays in actions.jsonl. Still RED after acting, or n8n down, is not.
        if after["level"] == "RED" or not report["n8n_ok"]:
            freed = sum(r["private_mb"] for r in killed)
            lines = [f"Brain Surgeon: pressure {before['level']} {before['commit_pct']}% commit, {before['free_mb']} MB free"
                     f" -> {after['level']} {after['commit_pct']}%, {after['free_mb']} MB free."]
            if killed:
                by_rule: dict[str, int] = {}
                for r in killed:
                    by_rule[r["rule"]] = by_rule.get(r["rule"], 0) + 1
                lines.append(f"Removed {len(killed)} process(es), ~{freed} MB: "
                             + ", ".join(f"{n} {k}" for k, n in by_rule.items()) + ".")
            if not report["n8n_ok"]:
                lines.append(f"n8n is NOT answering at {HEALTH_URL}.")
            if after["level"] == "RED":
                lines.append("Still RED after the last-resort list: protected processes (Claude sessions, TradingView, n8n) are holding the memory.")
            alert(" ".join(lines))
    if a.json:
        print(json.dumps(report, indent=1))
    else:
        b = before
        print(f"pressure {b['level']}: commit {b['commit_mb']}/{b['commit_limit_mb']} MB ({b['commit_pct']}%), "
              f"free {b['free_mb']} MB; {len(rows)} processes, {len(keep)} protected")
        for r in results:
            print(f"  {r['outcome']:<13} pid {r['pid']:<6} {r['name']:<16} {r['private_mb']:>6} MB  {r['rule']}: {r['why']}")
        if not results:
            print("  nothing to remove")
        if a.apply:
            print(f"after: {after['level']} commit {after['commit_pct']}%, free {after['free_mb']} MB; n8n ok: {report['n8n_ok']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
