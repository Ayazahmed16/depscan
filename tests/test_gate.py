"""The CI gate: `depscan scan --fail-on LEVEL` and the rules behind its exit status."""
import datetime as dt
import os
import subprocess
import sys
from pathlib import Path

import pytest

from depscan import gate
from depscan.__main__ import main
from depscan.review import ReviewStore
from depscan.scoring.config import load_config

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "tests" / "sample"
BENCH = ROOT / "benchmark"
KEV_KEY = "PyPI|pyspark|3.2.1|CVE-2022-33891"      # the only KEV-listed finding in the sample, action fix_now


def f(action, **kw):
    return {"id": kw.pop("id", "CVE-1"), "package": kw.pop("package", "p"), "action": action,
            "claim_status": kw.pop("claim_status", "matched"), "review_status": kw.pop("review_status", "pending"), **kw}


# ------------------------------------------------------------------ the rules
def test_levels_trigger_on_the_chosen_action_or_worse():
    findings = [f("fix_now", id="a"), f("verify_first", id="b"), f("monitor", id="c"), f("no_action", id="d")]
    ids = lambda level: [x["id"] for x in gate.failing(findings, level)]  # noqa: E731
    assert ids("fix_now") == ["a"]
    assert ids("verify_first") == ["a", "b"]
    assert ids("monitor") == ["a", "b", "c"]
    assert ids("any") == ["a", "b", "c", "d"]


def test_accepted_risk_and_false_positive_do_not_count_but_fix_now_does():
    findings = [f("fix_now", id="a", review_status="accept_risk"), f("fix_now", id="b", review_status="false_positive"),
                f("fix_now", id="c", review_status="fix_now"), f("fix_now", id="d", review_status="expired"), f("fix_now", id="e")]
    assert [x["id"] for x in gate.failing(findings, "fix_now")] == ["c", "d", "e"]     # an expired suppression needs review again


def test_a_contradicted_scanner_claim_does_not_count_an_unconfirmed_one_does():
    findings = [f("fix_now", id="a", claim_status="contradicted"), f("verify_first", id="b", claim_status="unconfirmed")]
    assert [x["id"] for x in gate.failing(findings, "verify_first")] == ["b"]


def test_an_unknown_level_is_an_error():
    with pytest.raises(ValueError):
        gate.failing([], "critical")


def test_summary_names_the_findings_and_a_pass_carries_the_reminder():
    ok, msg = gate.summary([], "fix_now")
    assert ok and "No findings does not prove a project is secure." in msg
    ok, msg = gate.summary([f("fix_now", id=f"CVE-{i}", package="pkg") for i in range(5)], "fix_now")
    assert not ok and "5 finding(s)" in msg and "pkg CVE-0, pkg CVE-1, pkg CVE-2 and 2 more" in msg


# ------------------------------------------------------------------ the command
def scan(*args, db=None):
    argv = ["scan", *map(str, args), "--offline", "--review-db", str(db or SAMPLE / "no-such-review.sqlite")]
    return main(argv)


def test_default_exit_status_is_zero_whatever_is_found(capsys):
    assert scan(SAMPLE / "requirements.txt", "--data-dir", SAMPLE / "snapshot") == 0


def test_a_vulnerable_input_fails_the_gate_and_a_clean_one_passes(capsys):
    assert scan(SAMPLE / "requirements.txt", "--data-dir", SAMPLE / "snapshot", "--fail-on", "fix_now") == 1
    err = capsys.readouterr().err
    assert "gate FAILED" in err and "pyspark CVE-2022-33891" in err
    assert scan(BENCH / "fixtures" / "clean-current", "--data-dir", BENCH / "snapshot", "--fail-on", "fix_now") == 0
    assert "gate passed" in capsys.readouterr().err


def test_stricter_levels_fail_less_than_looser_ones(capsys):
    codes = {lvl: scan(BENCH / "fixtures" / "clean-current", "--data-dir", BENCH / "snapshot", "--fail-on", lvl) for lvl in gate.LEVELS}
    assert codes["fix_now"] == 0 and codes["any"] == 1                                    # the one finding there is not urgent
    capsys.readouterr()


def test_the_report_goes_to_stdout_and_the_gate_message_to_stderr(capsys):
    scan(SAMPLE / "requirements.txt", "--data-dir", SAMPLE / "snapshot", "--fail-on", "fix_now")
    out, err = capsys.readouterr()
    assert "pyspark" in out and "gate FAILED" not in out and "gate FAILED" in err


def test_the_gate_also_works_when_writing_a_report_file(tmp_path, capsys):
    report = tmp_path / "r.md"
    assert scan(SAMPLE / "requirements.txt", "--data-dir", SAMPLE / "snapshot", "--fail-on", "fix_now", "--out", report) == 1
    assert report.read_text("utf-8").startswith("#") or "pyspark" in report.read_text("utf-8")


def test_a_recorded_decision_lets_the_gate_pass_until_it_expires(tmp_path, capsys):
    db, cfg = tmp_path / "r.sqlite", load_config()
    store = ReviewStore(db)
    other = "PyPI|pyspark|3.2.1|CVE-2023-32007"                                             # the second fix_now finding
    soon = (dt.date.today() + dt.timedelta(days=20)).isoformat()
    store.record("default", KEV_KEY, "accept_risk", "accepted for the demo environment", "Ana", soon, cfg=cfg, risk_score=96.0)
    assert scan(SAMPLE / "requirements.txt", "--data-dir", SAMPLE / "snapshot", "--fail-on", "fix_now", db=db) == 1   # one is still open
    err = capsys.readouterr().err
    assert "CVE-2023-32007" in err and "CVE-2022-33891" not in err                          # only the one still open is named
    store.record("default", other, "false_positive", "not reachable in our deployment", "Ana", soon, cfg=cfg, risk_score=73.8)
    assert scan(SAMPLE / "requirements.txt", "--data-dir", SAMPLE / "snapshot", "--fail-on", "fix_now", db=db) == 0
    capsys.readouterr()
    past = dt.datetime.now(dt.UTC) - dt.timedelta(days=60)                                  # a suppression that has since lapsed
    store.record("default", KEV_KEY, "accept_risk", "accepted last quarter, now lapsed", "Ana",
                 (past + dt.timedelta(days=10)).date().isoformat(), cfg=cfg, risk_score=96.0, now=past)
    assert scan(SAMPLE / "requirements.txt", "--data-dir", SAMPLE / "snapshot", "--fail-on", "fix_now", db=db) == 1
    assert "CVE-2022-33891" in capsys.readouterr().err


def test_contradicted_report_claims_do_not_fail_the_gate(capsys):
    assert scan(SAMPLE / "scan-report.json", "--data-dir", SAMPLE / "snapshot", "--fail-on", "any") == 1     # flask is truly affected
    err = capsys.readouterr().err
    assert "jinja2" not in err                                                              # the boundary-version claim was contradicted


def test_a_scan_that_cannot_run_is_status_two_not_one(tmp_path, capsys):
    empty = tmp_path / "data"
    empty.mkdir()
    assert scan(SAMPLE / "requirements.txt", "--data-dir", empty, "--fail-on", "fix_now") == 2


def test_the_gate_survives_a_console_that_cannot_print_arrows():
    """Regression: printing the Markdown report to a redirected Windows stream (cp1252) raised UnicodeEncodeError."""
    env = {**os.environ, "PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}
    r = subprocess.run([sys.executable, "-m", "depscan", "scan", str(SAMPLE / "requirements.txt"), "--data-dir", str(SAMPLE / "snapshot"),
                        "--offline", "--fail-on", "fix_now", "--review-db", str(SAMPLE / "none.sqlite")],
                       capture_output=True, cwd=ROOT, env=env)
    assert r.returncode == 1 and b"Traceback" not in r.stderr and b"gate FAILED" in r.stderr
