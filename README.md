# brain-surgeon

A memory guardian for a Windows machine that runs real services: a workflow
engine, a tunnel, bots, browser automation.

It started with an incident. One Chrome tab in an automation profile grew to
**15 GB**. Commit charge reached 57.6 of 58.9 GB, the workflow engine stopped
answering, and a phone agent that depended on it failed for ten hours. Its
health check then started a fresh PowerShell every five minutes that could never
finish, and **59 of them** piled up. Nothing on the machine was looking at memory
across the whole system, so nothing noticed.

brain-surgeon does that. Every few minutes it:

1. reads **commit charge and free physical memory** from Windows
   (`GetPerformanceInfo`) and grades the machine GREEN / AMBER / RED;
2. applies **named rules** from `policy.json`, so every process it kills is
   killed by a rule a person can read and never for its size alone;
3. **never touches anything protected**: by process name, command line or
   listening port, plus every ancestor of those (killing the `cmd.exe` that runs
   your server kills your server);
4. cuts Chrome at the **renderer**, never the browser. That one tab shows
   "Aw, Snap" and reloads, and your logins and other tabs stay;
5. logs every action to `state/actions.jsonl` with the rule, the pressure and a
   redacted command line.

It runs as a dry run unless you pass `--apply`.

## The rules

| Rule | Kills | When |
|---|---|---|
| `stuck_duplicate_script` | extra copies of the same scheduled script (keeps the newest) | 3+ copies, oldest 20+ min, any pressure |
| `bloated_automation_renderer` | one tab in a script-driven browser profile | ≥ 6 GB always, ≥ 3 GB at AMBER+ |
| `bloated_personal_renderer` | one tab in your own browser | RED and ≥ 6 GB only |
| `orphan_headless` | headless / Playwright browsers whose parent is gone | AMBER+ |
| `last_resort` | expendable apps (Loom, Spotify, OneDrive, Teams, Widgets…), then the biggest tabs, re-measuring after each kill | still RED after rules 1-4; tabs only at RED |

`last_resort` stops as soon as free memory is safe. It puts tabs that an
automation opened in the last few minutes **last**, because those are usually in
the middle of a task.

## churn.py: kills that don't stick

```
python churn.py --hours 24
process                       kills  MB freed  MB/kill  distinct PIDs
Loom.exe                         14      1610      115             14
```

When an app is killed 14 times with 14 different PIDs, it's respawning. Each
kill frees memory for about two minutes and then the app is back. The fix is to
turn off its autostart, and `churn.py` says so. A kill that has to be repeated
every cycle means the plan is wrong, not the machine.

## Install

```powershell
pip install psutil
# 1. Edit policy.json: protect what your work depends on, point health_url at your service.
python brain_surgeon.py                 # dry run: pressure, and what each rule WOULD kill
python -m pytest -q test_brain_surgeon.py
powershell -NoProfile -ExecutionPolicy Bypass -File register_task.ps1 -Minutes 5
```

`--json` prints a machine-readable report. When the machine is still RED after
acting, or `health_url` doesn't answer, a line is added to `state/alerts.log`
for your own monitoring to pick up.

## Design notes worth stealing

The comments and tests record the bugs that shaped the code. Each test replays
a real incident:

- **The lock that locked everyone out.** The single-instance check matched any
  process whose command line mentioned the script. The shell that launched it
  mentions it too, so every manual run exited with "another run is in progress".
  It now counts only Python interpreters, and excludes its own ancestors
  (a venv's `python.exe` is a launcher with the same command line).
- **A threshold the machine never reached while already failing.** RED was set at
  400 MB free. At 430 MB Windows itself was killing tabs, and the guardian still
  said AMBER and did nothing. The threshold is now set from what was observed.
- **Orphans need proof, not patience.** Checking that the parent process is gone
  is the evidence. A two-hour age floor added no safety and guaranteed that
  orphans survived the worst stretch.

## Limits

- Windows only. Python 3.10+ and `psutil`.
- It runs without elevation, so it can't kill elevated processes. It never
  restarts anything; it reports instead.

MIT licensed.
