"""Brain Surgeon rules against a replay of the 2026-09-16 21:35 EDT incident. No process is touched.

Pinned:
  * 59 copies of the n8n healthcheck shell: 58 die, the newest lives
  * the 15 GB tab in the scraper-automation profile dies at GREEN (it is over the any-pressure limit)
  * a 3.5 GB automation tab dies only at AMBER or worse
  * a tab in the operator's own browser survives AMBER and dies only at RED and >= 6 GB
  * anything on a protected port, on the protected list, or an ancestor of those, is never a candidate
  * a script with only two copies, or copies younger than 20 minutes, is left alone
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import brain_surgeon as bs  # noqa: E402

HC = r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ops\monitors\n8n_healthcheck.ps1"
AUTO_TAB = ('"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer '
            '--user-data-dir="C:\\Users\\you\\AppData\\Local\\scraper-automation\\chrome-profile" --remote-debugging-port=9222')
PERSONAL_TAB = ('"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer '
                '--user-data-dir="C:\\Users\\you\\AppData\\Local\\Google\\Chrome\\User Data"')


def row(pid, name, cmd, age=60, mb=10, ppid=1):
    return {"pid": pid, "ppid": ppid, "name": name, "cmd": cmd, "age_min": age, "private_mb": mb}


def rules_for(rows, level, keep=frozenset()):
    return {c["pid"]: c["rule"] for c in bs.candidates(rows, level, set(keep))}


class TestIncidentReplay(unittest.TestCase):
    def test_healthcheck_pileup_keeps_newest(self):
        rows = [row(1000 + i, "powershell.exe", HC, age=600 - i * 5) for i in range(59)]
        got = rules_for(rows, "GREEN")
        self.assertEqual(len(got), 58)
        newest = min(rows, key=lambda r: r["age_min"])["pid"]
        self.assertNotIn(newest, got)

    def test_fifteen_gb_automation_tab_dies_at_green(self):
        self.assertEqual(rules_for([row(29436, "chrome.exe", AUTO_TAB, mb=15046)], "GREEN"),
                         {29436: "bloated_automation_renderer"})

    def test_mid_size_automation_tab_needs_pressure(self):
        rows = [row(5, "chrome.exe", AUTO_TAB, mb=3500)]
        self.assertEqual(rules_for(rows, "GREEN"), {})
        self.assertEqual(rules_for(rows, "AMBER"), {5: "bloated_automation_renderer"})

    def test_personal_tab_only_at_red(self):
        rows = [row(7, "chrome.exe", PERSONAL_TAB, mb=9000)]
        self.assertEqual(rules_for(rows, "GREEN"), {})
        self.assertEqual(rules_for(rows, "AMBER"), {})
        self.assertEqual(rules_for(rows, "RED"), {7: "bloated_personal_renderer"})
        self.assertEqual(rules_for([row(8, "chrome.exe", PERSONAL_TAB, mb=5000)], "RED"), {})

    def test_protected_pids_are_never_candidates(self):
        rows = [row(1000 + i, "powershell.exe", HC, age=600 - i) for i in range(5)]
        keep = {1000, 1001, 1002, 1003, 1004}
        self.assertEqual(rules_for(rows, "RED", keep), {})

    def test_few_or_young_copies_left_alone(self):
        two = [row(1, "powershell.exe", HC, age=500), row(2, "powershell.exe", HC, age=400)]
        young = [row(10 + i, "powershell.exe", HC, age=5 + i) for i in range(6)]
        self.assertEqual(rules_for(two, "RED"), {})
        self.assertEqual(rules_for(young, "RED"), {})

    def test_protected_list_covers_n8n_and_monitors_by_name_and_ancestry(self):
        rows = [row(9080, "cmd.exe", r"cmd.exe /c C:\ops\services\start_n8n.bat", ppid=1),
                row(4632, "node.exe", r"node C:\Users\you\AppData\Roaming\npm\node_modules\n8n\bin\n8n start", ppid=9080),
                row(500, "python.exe", r"python -u personal_wait_for_mail.py --stream", ppid=1),
                row(600, "claude.exe", "claude", ppid=1)]
        keep = bs.protected_pids(rows)
        for pid in (4632, 9080, 500, 600):
            self.assertIn(pid, keep)



class TestLastResort(unittest.TestCase):
    """2026-09-18: RED for an hour, 388 MB free, memory spread across ordinary apps, no rule matched."""

    def test_apps_first_then_biggest_tabs_and_never_protected(self):
        rows = [row(1, "claude.exe", "claude", mb=900),
                row(2, "TradingView.exe", "TradingView", mb=2600),
                row(3, "Loom.exe", "Loom --type=renderer", mb=300),
                row(4, "Loom.exe", "Loom", mb=900),
                row(5, "chrome.exe", PERSONAL_TAB, mb=1200),
                row(6, "chrome.exe", PERSONAL_TAB, mb=2400),
                row(7, "chrome.exe", PERSONAL_TAB, mb=200),
                row(8, "chrome.exe", PERSONAL_TAB + " --extension-process", mb=1500)]
        keep = {1, 2}
        order = [c["pid"] for c in bs.last_resort(rows, keep)]
        self.assertEqual(order, [4, 3, 6, 5])       # Loom biggest first, then tabs biggest first
        self.assertNotIn(1, order)                   # Claude session
        self.assertNotIn(2, order)                   # TradingView
        self.assertNotIn(7, order)                   # small tab left alone
        self.assertNotIn(8, order)                   # extensions are not tabs

if __name__ == "__main__":
    unittest.main()


class TheDayItWatchedTheMachineDie(unittest.TestCase):
    """2026-09-22. Free memory sat at 430 MB, the surgeon called it AMBER, took no
    action, and Windows killed the same Chrome tab five times while an approved carrier
    registration could not be submitted. Two rules were wrong and both are pinned here.
    """

    ORPHAN = (r'"C:\Users\you\AppData\Local\ms-playwright\chromium-1234\chrome.exe" '
              r'--headless --remote-debugging-port=0')

    def test_a_young_orphan_is_reaped_now_not_in_two_hours(self):
        """The rule already proves the parent is gone. The extra 120-minute wait meant
        orphans from a crashed run survived exactly the stretch when memory was tight,
        and two of them had to be killed by hand."""
        rows = [row(9001, "chrome.exe", self.ORPHAN, age=5, mb=73, ppid=424242)]
        self.assertEqual(rules_for(rows, "AMBER").get(9001), "orphan_headless")

    def test_an_orphan_seconds_old_is_still_left_alone(self):
        """A floor remains, so a process whose parent has not yet been recorded is not
        mistaken for an orphan."""
        rows = [row(9002, "chrome.exe", self.ORPHAN, age=0.5, mb=73, ppid=424242)]
        self.assertNotIn(9002, rules_for(rows, "AMBER"))

    def test_an_orphan_whose_parent_is_alive_is_never_touched(self):
        """Parentage is the evidence, not age. A live run must survive at any age."""
        rows = [row(9003, "chrome.exe", self.ORPHAN, age=300, mb=900, ppid=777),
                row(777, "python.exe", r"python.exe C:\ops\run.py")]
        self.assertNotIn(9003, rules_for(rows, "AMBER"))

    def test_430mb_free_is_red_not_amber(self):
        """The threshold the machine never reached while already failing. At 430 MB the
        tab was being killed by Windows, so last_resort must be allowed to run."""
        self.assertLess(430, bs.POLICY["pressure"]["red_free_mb"])

    def test_red_still_leaves_room_below_amber(self):
        """RED has to stay under AMBER or the levels invert and every run is RED."""
        p = bs.POLICY["pressure"]
        self.assertLess(p["red_free_mb"], p["amber_free_mb"])

    def test_last_resort_frees_past_the_red_line(self):
        """Stopping at exactly RED would leave the machine one tab from failing again."""
        self.assertGreater(bs.POLICY["rules"]["last_resort"]["stop_when_free_mb"],
                           bs.POLICY["pressure"]["red_free_mb"])


class ExpendableAppsAtAmber(unittest.TestCase):
    """The operator, 2026-09-22: "cut processes that it's clear we're not using or don't need."
    Loom and the rest are that list. A browser TAB is not, because it can hold unsaved
    work, so tabs stay RED-only."""

    ROWS = [row(5001, "Loom.exe", "loom", mb=400),
            row(5002, "SearchHost.exe", "search", mb=120),
            row(5003, "chrome.exe", PERSONAL_TAB + " --type=renderer", mb=1500)]

    def test_amber_reaps_expendable_apps(self):
        got = {c["pid"] for c in bs.last_resort(self.ROWS, set(), "AMBER")}
        self.assertEqual(got, {5001, 5002})

    def test_amber_leaves_browser_tabs_alone(self):
        got = {c["pid"] for c in bs.last_resort(self.ROWS, set(), "AMBER")}
        self.assertNotIn(5003, got, "a tab may hold unsaved work; that is a RED decision")

    def test_red_still_reaches_the_tabs(self):
        got = {c["pid"] for c in bs.last_resort(self.ROWS, set(), "RED")}
        self.assertEqual(got, {5001, 5002, 5003})

    def test_protected_processes_are_never_offered_at_either_level(self):
        for lvl in ("AMBER", "RED"):
            got = {c["pid"] for c in bs.last_resort(self.ROWS, {5001, 5002, 5003}, lvl)}
            self.assertEqual(got, set(), f"keep-set ignored at {lvl}")

    def test_the_reason_names_the_level_it_acted_at(self):
        why = bs.last_resort(self.ROWS, set(), "AMBER")[0]["why"]
        self.assertIn("AMBER", why, "the log must say which pressure justified the kill")


class TheLockThatLockedEveryoneOut(unittest.TestCase):
    """2026-09-22. Every manual `--apply` answered "another Brain Surgeon run is in
    progress" while none was. `already_running` matched ANY process whose command line
    mentioned brain_surgeon.py, and the shell that launches it carries the whole command
    line, as does any sibling shell typed in the same second. The effect was that the
    surgeon could be run only by Task Scheduler, which is exactly when a person most
    wants to run it by hand, and the machine sat at 430 MB free all afternoon.
    """

    def test_only_a_python_interpreter_counts_as_a_run(self):
        import inspect
        src = inspect.getsource(bs.already_running)
        self.assertIn("python.exe", src,
                      "the check must identify an interpreter, not a mention of the filename")

    def test_a_shell_mentioning_the_file_is_not_a_run(self):
        """The exact shape that blocked it: bash -c '... brain_surgeon.py --apply'."""
        import inspect
        src = inspect.getsource(bs.already_running)
        self.assertTrue(
            'p.info["name"]' in src and "continue" in src,
            "a non-python process must be skipped before the cmdline is examined")


class TestYoungAutomationTabLast(unittest.TestCase):
    """2026-09-25 00:18 ET: a 2-minute-old 793 MB checkout tab in the :9222 automation Chrome was killed first."""

    def test_young_automation_tab_goes_last(self):
        auto = "chrome.exe --type=renderer --remote-debugging-port=9222"
        rows = [dict(row(1, "chrome.exe", auto, mb=793), age_min=2),
                dict(row(2, "chrome.exe", PERSONAL_TAB, mb=750), age_min=300),
                dict(row(3, "chrome.exe", auto, mb=720), age_min=90)]
        order = [c["pid"] for c in bs.last_resort(rows, set())]
        self.assertEqual(order[-1], 1)
        self.assertEqual(order[:2], [2, 3])
