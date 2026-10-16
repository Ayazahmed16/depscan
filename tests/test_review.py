"""Phase 6: reviewer decisions, expiry, the audit log and its tamper evidence."""
import datetime as dt
import json
import sqlite3

import pytest

from depscan.pipeline import DataBundle, apply_reviews, scan_files
from depscan.report import render_html, render_markdown
from depscan.review import ReviewError, ReviewStore, finding_key
from depscan.scoring.config import load_config

CFG = load_config()
UTC = dt.UTC
NOW = dt.datetime(2030, 3, 1, 12, 0, tzinfo=UTC)
KEY = "PyPI|alpha|1.0|CVE-2030-0001"
LONG_ENOUGH = "accepted until the vendor ships the patch"


@pytest.fixture()
def store(tmp_path):
    return ReviewStore(tmp_path / "state" / "review.sqlite")


def rec(store, decision="accept_risk", *, key=KEY, expires="2030-03-20", reviewer="Ana", note=LONG_ENOUGH, risk=40.0, now=NOW, project="p"):
    return store.record(project, key, decision, note, reviewer, expires, cfg=CFG, risk_score=risk, now=now)


# ---------------------------------------------------------------- recording and reading
def test_a_decision_is_stored_with_who_when_why_and_expiry(store):
    r = rec(store)
    assert r == {"decision": "accept_risk", "note": LONG_ENOUGH, "reviewer": "Ana", "at": "2030-03-01T12:00:00Z", "expires": "2030-03-20"}
    cur = store.current("p", now=NOW)[KEY]
    assert cur["status"] == "accept_risk" and cur["reviewer"] == "Ana" and cur["expires"] == "2030-03-20"


def test_fix_now_needs_no_expiry_and_never_expires(store):
    rec(store, "fix_now", expires=None)
    assert store.current("p", now=NOW + dt.timedelta(days=3650))[KEY]["status"] == "fix_now"


def test_reviewer_and_note_are_stripped(store):
    r = rec(store, reviewer="  Ana  ", note="   " + LONG_ENOUGH + "  ")
    assert r["reviewer"] == "Ana" and r["note"] == LONG_ENOUGH


def test_projects_are_separate(store):
    rec(store, project="one")
    assert KEY in store.current("one", now=NOW) and store.current("two", now=NOW) == {}


def test_a_new_decision_replaces_the_current_one_but_history_keeps_both(store):
    rec(store, "accept_risk")
    rec(store, "fix_now", expires=None, note="changed our mind, scheduling the upgrade")
    assert store.current("p", now=NOW)[KEY]["status"] == "fix_now"
    assert [e["action"] for e in store.audit("p", KEY)] == ["fix_now", "accept_risk"]       # newest first, both kept


# ---------------------------------------------------------------- the rules
@pytest.mark.parametrize("kwargs,message", [
    ({"decision": "ignore"}, "decision must be one of"),
    ({"reviewer": ""}, "reviewer name is required"),
    ({"reviewer": "   "}, "reviewer name is required"),
    ({"note": "ok"}, "reason of at least 10 characters"),
    ({"note": "          "}, "reason of at least 10 characters"),
    ({"expires": None}, "needs an expiry date"),
    ({"expires": "next week"}, "YYYY-MM-DD"),
    ({"expires": "2030-03-01"}, "must be in the future"),      # today is not the future
    ({"expires": "2030-02-01"}, "must be in the future"),
    ({"expires": "2030-09-30"}, "at most 180 days"),
])
def test_rules_reject_bad_decisions_and_say_which_rule(store, kwargs, message):
    with pytest.raises(ReviewError, match=message):
        rec(store, **kwargs)
    assert store.current("p", now=NOW) == {} and store.audit() == []          # nothing was stored or logged


def test_fix_now_rejects_an_expiry_date(store):
    with pytest.raises(ReviewError, match="fix_now does not take an expiry"):
        rec(store, "fix_now", expires="2030-03-20")


def test_suppression_length_limit_is_180_days_and_30_for_critical_findings(store):
    last_ok = (NOW.date() + dt.timedelta(days=180)).isoformat()
    too_long = (NOW.date() + dt.timedelta(days=181)).isoformat()
    rec(store, expires=last_ok, risk=40)                                          # exactly 180: allowed
    with pytest.raises(ReviewError, match="at most 180 days"):
        rec(store, expires=too_long, risk=40)
    in_30 = (NOW.date() + dt.timedelta(days=30)).isoformat()
    in_31 = (NOW.date() + dt.timedelta(days=31)).isoformat()
    rec(store, key="k2", expires=in_30, risk=60)                                  # critical tier boundary: 30 days allowed
    with pytest.raises(ReviewError, match="critical-tier finding can last at most 30 days"):
        rec(store, key="k2b", expires=in_31, risk=60)                             # exactly 60 IS the critical tier: 31 days is refused
    with pytest.raises(ReviewError, match="critical-tier finding can last at most 30 days"):
        rec(store, key="k3", expires=in_31, risk=96)
    rec(store, key="k4", expires=in_31, risk=59.9)                                # just below the tier: the 180-day limit applies


# ---------------------------------------------------------------- expiry
def test_a_suppression_is_valid_through_its_expiry_date_and_expired_after(store):
    rec(store, expires="2030-03-20")
    assert store.current("p", now=dt.datetime(2030, 3, 20, 23, 59, tzinfo=UTC))[KEY]["status"] == "accept_risk"
    assert store.current("p", now=dt.datetime(2030, 3, 21, 0, 1, tzinfo=UTC))[KEY]["status"] == "expired"


def test_expiry_is_logged_once_by_the_system(store):
    rec(store, expires="2030-03-20")
    later = dt.datetime(2030, 4, 1, tzinfo=UTC)
    assert store.sweep_expired("p", now=later) == [KEY]
    assert store.sweep_expired("p", now=later) == []                             # not logged twice
    expired = [e for e in store.audit("p") if e["action"] == "expired"]
    assert len(expired) == 1 and expired[0]["reviewer"] == "system" and "expired" in expired[0]["note"]


def test_deciding_again_after_expiry_starts_a_fresh_cycle(store):
    rec(store, expires="2030-03-20")
    store.sweep_expired("p", now=dt.datetime(2030, 4, 1, tzinfo=UTC))
    rec(store, expires="2030-04-30", now=dt.datetime(2030, 4, 2, tzinfo=UTC))
    assert store.current("p", now=dt.datetime(2030, 4, 3, tzinfo=UTC))[KEY]["status"] == "accept_risk"
    store.sweep_expired("p", now=dt.datetime(2030, 6, 1, tzinfo=UTC))            # the second suppression lapses and IS logged
    assert [e["action"] for e in store.audit("p")].count("expired") == 2


def test_fix_now_is_never_swept(store):
    rec(store, "fix_now", expires=None)
    assert store.sweep_expired("p", now=dt.datetime(2040, 1, 1, tzinfo=UTC)) == []


# ---------------------------------------------------------------- revoke
def test_revoking_returns_the_finding_to_needing_review_and_keeps_history(store):
    rec(store)
    store.revoke("p", KEY, "the vendor patch shipped, reviewing again", "Ben", cfg=CFG, now=NOW)
    assert store.current("p", now=NOW) == {}
    log = store.audit("p", KEY)
    assert [e["action"] for e in log] == ["revoked", "accept_risk"] and log[0]["reviewer"] == "Ben"


def test_revoke_rules(store):
    with pytest.raises(ReviewError, match="no decision on this finding"):
        store.revoke("p", KEY, LONG_ENOUGH, "Ben", cfg=CFG)
    rec(store)
    with pytest.raises(ReviewError, match="reviewer name"):
        store.revoke("p", KEY, LONG_ENOUGH, "", cfg=CFG)
    with pytest.raises(ReviewError, match="reason of at least"):
        store.revoke("p", KEY, "no", "Ben", cfg=CFG)
    assert KEY in store.current("p", now=NOW)                                     # still decided: every revoke attempt failed


# ---------------------------------------------------------------- the audit log
def test_audit_is_newest_first_filterable_and_limited(store):
    for i in range(5):
        rec(store, key=f"PyPI|p{i}|1|X{i}", now=NOW + dt.timedelta(minutes=i))
    rec(store, key="other", project="q")
    assert [e["key"] for e in store.audit("p", limit=2)] == ["PyPI|p4|1|X4", "PyPI|p3|1|X3"]
    assert len(store.audit("p")) == 5 and len(store.audit()) == 6 and len(store.audit("q")) == 1
    assert [e["key"] for e in store.audit(key="other")] == ["other"]


def test_audit_log_refuses_update_and_delete(store):
    rec(store)
    db = sqlite3.connect(store.path)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.execute("UPDATE audit_log SET note='rewritten'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.execute("DELETE FROM audit_log")
    db.close()
    assert store.audit()[0]["note"] == LONG_ENOUGH


def test_hash_chain_is_intact_for_normal_use(store):
    assert store.verify_audit() == (True, None, 0)
    rec(store)
    rec(store, key="b")
    store.revoke("p", "b", LONG_ENOUGH, "Ben", cfg=CFG, now=NOW)
    store.sweep_expired("p", now=dt.datetime(2031, 1, 1, tzinfo=UTC))
    ok, bad, n = store.verify_audit()
    assert ok and bad is None and n == 4


def _unprotect(path):
    """What a person with write access to the file could do: remove the triggers first."""
    db = sqlite3.connect(path)
    db.executescript("DROP TRIGGER audit_no_update; DROP TRIGGER audit_no_delete;")
    return db


def test_editing_history_is_detected(store):
    rec(store)
    rec(store, key="b")
    rec(store, key="c")
    db = _unprotect(store.path)
    db.execute("UPDATE audit_log SET note='something else entirely' WHERE id=2")
    db.commit()
    db.close()
    assert store.verify_audit() == (False, 2, 1)                                  # entry 2 is where the chain breaks


def test_deleting_history_is_detected(store):
    for k in "abc":
        rec(store, key=k)
    db = _unprotect(store.path)
    db.execute("DELETE FROM audit_log WHERE id=2")
    db.commit()
    db.close()
    ok, bad, _ = store.verify_audit()
    assert not ok and bad == 3                                                    # entry 3 no longer follows entry 1


def test_the_whole_state_survives_a_restart_and_leaves_no_open_handles(tmp_path):
    path = tmp_path / "review.sqlite"
    rec(ReviewStore(path))
    again = ReviewStore(path)
    assert again.current("p", now=NOW)[KEY]["reviewer"] == "Ana" and again.verify_audit()[0]
    path.unlink()                                                                 # raises on Windows if a connection were left open


# ---------------------------------------------------------------- pipeline integration (synthetic advisories, see conftest.py)
def scan(data_dir, store=None, project="p", today=dt.date(2030, 3, 2), content=b"alpha==1.0\nbeta==2.0\n"):
    return scan_files([("requirements.txt", content)], DataBundle(data_dir), review_store=store, project=project, today=today)


def alpha(result):
    return next(f for f in result["findings"] if f["package"] == "alpha")


def test_findings_have_a_stable_key_that_includes_package_version_and_advisory(data_dir):
    f = alpha(scan(data_dir))
    assert f["key"] == KEY == finding_key(f)
    assert alpha(scan(data_dir))["key"] == f["key"]
    assert alpha(scan(data_dir, content=b"alpha==1.2\n"))["key"] != f["key"]       # a different version is a different finding


def test_without_a_store_everything_is_pending(data_dir):
    r = scan(data_dir)
    assert all(f["review"] is None and f["review_status"] == "pending" for f in r["findings"])
    assert r["review_summary"]["needs_review"] == len(r["findings"]) == 2


def test_a_decision_is_attached_but_nothing_is_hidden_or_rescored(data_dir, store):
    before = scan(data_dir)
    store.record("p", KEY, "accept_risk", LONG_ENOUGH, "Ana", "2030-03-20", cfg=CFG, risk_score=40, now=NOW)
    after = scan(data_dir, store)
    a, b = alpha(before), alpha(after)
    assert b["review_status"] == "accept_risk" and b["review"]["reviewer"] == "Ana" and b["review"]["expires"] == "2030-03-20"
    assert len(after["findings"]) == len(before["findings"])                       # still listed
    assert (b["risk"], b["trust"], b["action"], b["recommendation"]) == (a["risk"], a["trust"], a["action"], a["recommendation"])
    s = after["review_summary"]
    assert (s["accept_risk"], s["pending"], s["needs_review"]) == (1, 1, 1)


def test_an_expired_suppression_needs_review_again_and_is_logged(data_dir, store):
    store.record("p", KEY, "false_positive", LONG_ENOUGH, "Ana", "2030-03-20", cfg=CFG, risk_score=40, now=NOW)
    during = scan(data_dir, store, today=dt.date(2030, 3, 15))
    assert alpha(during)["review_status"] == "false_positive" and during["review_summary"]["needs_review"] == 1
    after = scan(data_dir, store, today=dt.date(2030, 4, 1))
    assert alpha(after)["review_status"] == "expired" and after["review_summary"]["expired"] == 1
    assert after["review_summary"]["needs_review"] == 2                            # the expired one counts as needing review
    assert [e["action"] for e in store.audit("p", KEY)][0] == "expired"


def test_decisions_do_not_leak_between_projects(data_dir, store):
    store.record("p", KEY, "fix_now", LONG_ENOUGH, "Ana", None, cfg=CFG, now=NOW)
    assert alpha(scan(data_dir, store, project="p"))["review_status"] == "fix_now"
    assert alpha(scan(data_dir, store, project="other"))["review_status"] == "pending"


def test_apply_reviews_counts_every_status(store):
    fs = [{"key": f"k{i}"} for i in range(5)]
    for k, d, exp in (("k0", "fix_now", None), ("k1", "accept_risk", "2030-03-20"), ("k2", "false_positive", "2030-03-10")):
        store.record("p", k, d, LONG_ENOUGH, "Ana", exp, cfg=CFG, now=dt.datetime(2030, 3, 1, tzinfo=UTC))
    counts = apply_reviews(fs, store, "p", now=dt.datetime(2030, 3, 15, tzinfo=UTC))
    assert counts == {"pending": 2, "expired": 1, "fix_now": 1, "accept_risk": 1, "false_positive": 0, "needs_review": 3}


# ---------------------------------------------------------------- reports
def test_reports_show_decisions_expiry_and_the_review_summary(data_dir, store):
    store.record("p", KEY, "accept_risk", 'waiting for the patch <b>soon</b>', "Ana", "2030-03-20", cfg=CFG, risk_score=40, now=NOW)
    r = scan(data_dir, store)
    md, page = render_markdown(r), render_html(r)
    assert "1 need review" in md and "Suppressed findings stay listed" in md
    assert "## Reviewer decisions" in md and "risk accepted | Ana | 2030-03-01 | 2030-03-20" in md
    assert 'Review: risk accepted by Ana on 2030-03-01 until 2030-03-20: "waiting for the patch <b>soon</b>"' in md
    assert "needs review (no decision recorded)" in md                              # the other finding
    assert "Reviewer decisions" in page and "&lt;b&gt;soon&lt;/b&gt;" in page and "<b>soon</b>" not in page   # escaped in HTML


def test_an_expired_decision_is_called_out_in_the_report(data_dir, store):
    store.record("p", KEY, "accept_risk", LONG_ENOUGH, "Ana", "2030-03-20", cfg=CFG, risk_score=40, now=NOW)
    md = render_markdown(scan(data_dir, store, today=dt.date(2030, 5, 1)))
    assert "EXPIRED, needs review" in md and "That decision has EXPIRED" in md


def test_reports_still_render_without_review_data(data_dir):
    r = scan(data_dir)
    for k in ("review_summary",):
        r.pop(k)
    for f in r["findings"]:
        f.pop("review"), f.pop("review_status")
    assert "needs review" in render_markdown(r) and "Reviewer decisions" not in render_markdown(r)
    assert json.dumps(render_html(r))


# ---------------------------------------------------------------- command line, end to end
def test_cli_review_flow(data_dir, tmp_path, capsys):
    from depscan.__main__ import main
    reqs = tmp_path / "requirements.txt"
    reqs.write_bytes(b"alpha==1.0\n")
    result, db = tmp_path / "result.json", tmp_path / "state" / "review.sqlite"
    base = ["--review-db", str(db)]
    soon = (dt.date.today() + dt.timedelta(days=10)).isoformat()
    far = (dt.date.today() + dt.timedelta(days=100)).isoformat()

    assert main(["scan", str(reqs), "--data-dir", str(data_dir), "--offline", "--out", str(result), *base]) == 0
    assert not db.exists()                                                          # a scan alone never creates review state
    assert main(["audit", *base]) == 0 and "nothing has been decided" in capsys.readouterr().out

    capsys.readouterr()
    assert main(["review", str(result), "--list", *base]) == 0
    listing = capsys.readouterr().out
    assert KEY in listing and "needs review" in listing

    def review(*a):
        return main(["review", str(result), KEY, *a, *base])

    assert review("accept_risk", "--reviewer", "Ana", "--note", "short", "--expires", soon) == 2          # too short a reason
    assert "reason of at least 10 characters" in capsys.readouterr().err
    assert review("accept_risk", "--reviewer", "Ana", "--note", LONG_ENOUGH) == 2                         # no expiry
    assert "needs an expiry date" in capsys.readouterr().err
    assert review("accept_risk", "--reviewer", "Ana", "--note", LONG_ENOUGH, "--expires", far) == 2       # critical finding: 30 days max
    assert "critical-tier finding can last at most 30 days" in capsys.readouterr().err
    assert main(["review", str(result), "NOPE|x|1|y", "fix_now", "--reviewer", "Ana", "--note", LONG_ENOUGH, *base]) == 2
    assert "no finding with key" in capsys.readouterr().err
    assert not db.exists() or ReviewStore(db).audit() == []                                                # nothing recorded so far

    assert review("accept_risk", "--reviewer", "Ana", "--note", LONG_ENOUGH, "--expires", soon) == 0
    assert "recorded: risk accepted by Ana" in capsys.readouterr().out

    assert main(["scan", str(reqs), "--data-dir", str(data_dir), "--offline", "--out", str(result), *base]) == 0
    assert json.loads(result.read_text())["findings"][0]["review_status"] == "accept_risk"                 # the rescan sees it
    assert main(["scan", str(reqs), "--data-dir", str(data_dir), "--offline", *base]) == 0
    assert "risk accepted by Ana" in capsys.readouterr().out

    assert main(["audit", "--verify", *base]) == 0 and "audit log intact: 1 entries" in capsys.readouterr().out
    assert main(["audit", *base]) == 0 and "accept_risk" in capsys.readouterr().out

    assert review("revoke", "--reviewer", "Ben", "--note", "patch shipped, reviewing again") == 0
    assert "revoked" in capsys.readouterr().out and ReviewStore(db).current("default") == {}
    assert reqs.read_bytes() == b"alpha==1.0\n"                                                            # the dependency file was never touched


def test_cli_audit_verify_fails_loudly_on_tampering(tmp_path, capsys):
    from depscan.__main__ import main
    db = tmp_path / "review.sqlite"
    store = ReviewStore(db)
    rec(store)
    rec(store, key="b")
    conn = _unprotect(db)
    conn.execute("UPDATE audit_log SET reviewer='someone else' WHERE id=1")
    conn.commit()
    conn.close()
    assert main(["audit", "--verify", "--review-db", str(db)]) == 1
    assert "AUDIT LOG BROKEN at entry 1" in capsys.readouterr().out
