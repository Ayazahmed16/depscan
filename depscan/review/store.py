"""Reviewer decisions and the audit log. This is what makes "a human decides" real.

depscan never changes your dependency files. A reviewer can record one of three decisions on a finding:

    fix_now          confirmed: this will be fixed
    accept_risk      a known risk is accepted for now          (a suppression: must expire)
    false_positive   the finding does not really apply         (a suppression: must expire)

Rules (config/scoring.yaml, review:):
  * a reviewer name and a reason are required;
  * suppressions need an expiry date, no more than max_suppression_days away (a shorter limit for findings
    in the critical risk tier), so a forgotten decision cannot hide a finding forever;
  * a suppressed finding stays visible, with its reason and expiry; when the expiry passes it needs review again;
  * a decision never changes the risk score, the trust score or the computed next step.

Storage is a local SQLite file (default: state/review.sqlite, git-ignored). Two tables:
  decisions   the current decision per finding (one row each)
  audit_log   every event, append-only: database triggers refuse UPDATE and DELETE, and each row carries a hash
              of the previous row, so editing or removing history is detectable with verify_audit().

Limit, stated plainly: reviewer names are typed in, not authenticated, and a person with write access to the file
can rebuild the whole chain. The hash chain detects accidental damage and casual edits, not a determined attacker.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

DECISIONS = ("fix_now", "accept_risk", "false_positive")
SUPPRESSIONS = ("accept_risk", "false_positive")
GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    project TEXT NOT NULL, key TEXT NOT NULL, decision TEXT NOT NULL, reviewer TEXT NOT NULL, note TEXT NOT NULL,
    at TEXT NOT NULL, expires TEXT, risk_score REAL, lapse_logged INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project, key)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, project TEXT NOT NULL, key TEXT NOT NULL,
    action TEXT NOT NULL, reviewer TEXT NOT NULL, note TEXT NOT NULL, expires TEXT,
    prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""


class ReviewError(ValueError):
    """A decision that breaks the review rules. The message says which rule, in plain words."""


def finding_key(finding: dict) -> str:
    """Stable identity of a finding: the same advisory on the same package version in the same ecosystem."""
    return f"{finding['ecosystem']}|{finding['package']}|{finding['version']}|{finding['id']}"


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def stamp(now: dt.datetime) -> str:
    return now.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _entry_hash(prev: str, fields: dict) -> str:
    return hashlib.sha256((prev + "|" + json.dumps(fields, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()


class ReviewStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._tx() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        """One transaction: commit on success, roll back on error, and always close (open handles break Windows)."""
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    # ------------------------------------------------------------------ validation (pure, so the UI/API can reuse it)
    @staticmethod
    def validate(decision: str, note: str, reviewer: str, expires: str | None, *, risk_score: float | None,
                 cfg: dict, today: dt.date) -> None:
        rules = cfg["review"]
        if decision not in DECISIONS:
            raise ReviewError(f"decision must be one of {', '.join(DECISIONS)}")
        if not reviewer or not reviewer.strip():
            raise ReviewError("a reviewer name is required")
        if len((note or "").strip()) < rules["min_note_chars"]:
            raise ReviewError(f"a reason of at least {rules['min_note_chars']} characters is required")
        if decision not in SUPPRESSIONS:
            if expires:
                raise ReviewError("fix_now does not take an expiry date")
            return
        if not expires:
            raise ReviewError(f"{decision} suppresses a finding, so it needs an expiry date")
        try:
            end = dt.date.fromisoformat(expires)
        except ValueError:
            raise ReviewError("the expiry date must look like YYYY-MM-DD") from None
        if end <= today:
            raise ReviewError("the expiry date must be in the future")
        critical = risk_score is not None and risk_score >= cfg["risk"]["tiers"]["critical"]
        limit = rules["max_suppression_days_critical"] if critical else rules["max_suppression_days"]
        if (end - today).days > limit:
            raise ReviewError(f"a suppression of a {'critical-tier ' if critical else ''}finding can last at most {limit} days "
                              f"(until {(today + dt.timedelta(days=limit)).isoformat()})")

    # ------------------------------------------------------------------ writing
    def _append(self, db: sqlite3.Connection, *, now: dt.datetime, project: str, key: str, action: str,
                reviewer: str, note: str, expires: str | None) -> None:
        row = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else GENESIS
        fields = {"at": stamp(now), "project": project, "key": key, "action": action, "reviewer": reviewer,
                  "note": note, "expires": expires}
        db.execute("INSERT INTO audit_log (at, project, key, action, reviewer, note, expires, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?)",
                   (*fields.values(), prev, _entry_hash(prev, fields)))

    def record(self, project: str, key: str, decision: str, note: str, reviewer: str, expires: str | None, *,
               cfg: dict, risk_score: float | None = None, now: dt.datetime | None = None) -> dict:
        now = now or utc_now()
        self.validate(decision, note, reviewer, expires, risk_score=risk_score, cfg=cfg, today=now.date())
        note, reviewer = note.strip(), reviewer.strip()
        with self._tx() as db:
            db.execute("INSERT OR REPLACE INTO decisions (project, key, decision, reviewer, note, at, expires, risk_score) VALUES (?,?,?,?,?,?,?,?)",
                       (project, key, decision, reviewer, note, stamp(now), expires, risk_score))
            self._append(db, now=now, project=project, key=key, action=decision, reviewer=reviewer, note=note, expires=expires)
        return {"decision": decision, "note": note, "reviewer": reviewer, "at": stamp(now), "expires": expires}

    def revoke(self, project: str, key: str, note: str, reviewer: str, *, cfg: dict, now: dt.datetime | None = None) -> None:
        """Take a decision back: the finding needs review again. The history is kept."""
        now = now or utc_now()
        if not reviewer or not reviewer.strip():
            raise ReviewError("a reviewer name is required")
        if len((note or "").strip()) < cfg["review"]["min_note_chars"]:
            raise ReviewError(f"a reason of at least {cfg['review']['min_note_chars']} characters is required")
        with self._tx() as db:
            if not db.execute("SELECT 1 FROM decisions WHERE project=? AND key=?", (project, key)).fetchone():
                raise ReviewError("there is no decision on this finding to revoke")
            db.execute("DELETE FROM decisions WHERE project=? AND key=?", (project, key))
            self._append(db, now=now, project=project, key=key, action="revoked", reviewer=reviewer.strip(), note=note.strip(), expires=None)

    def sweep_expired(self, project: str, *, now: dt.datetime | None = None) -> list[str]:
        """Log (once) every suppression whose expiry has passed. Returns the keys that lapsed this time."""
        now = now or utc_now()
        lapsed = []
        with self._tx() as db:
            for r in db.execute("SELECT * FROM decisions WHERE project=? AND expires IS NOT NULL AND expires < ? AND lapse_logged=0",
                                (project, now.date().isoformat())).fetchall():
                self._append(db, now=now, project=project, key=r["key"], action="expired", reviewer="system",
                             note=f"the {r['decision'].replace('_', ' ')} decision by {r['reviewer']} expired", expires=r["expires"])
                db.execute("UPDATE decisions SET lapse_logged=1 WHERE project=? AND key=?", (project, r["key"]))
                lapsed.append(r["key"])
        return lapsed

    # ------------------------------------------------------------------ reading
    def current(self, project: str, *, now: dt.datetime | None = None) -> dict[str, dict]:
        """{key: record} with `status`: accept_risk / false_positive / fix_now, or `expired` for a lapsed suppression."""
        today = (now or utc_now()).date().isoformat()
        out = {}
        with self._tx() as db:
            for r in db.execute("SELECT * FROM decisions WHERE project=?", (project,)).fetchall():
                expired = r["expires"] is not None and r["expires"] < today
                out[r["key"]] = {"decision": r["decision"], "note": r["note"], "reviewer": r["reviewer"], "at": r["at"],
                                 "expires": r["expires"], "status": "expired" if expired else r["decision"]}
        return out

    def audit(self, project: str | None = None, key: str | None = None, limit: int = 500) -> list[dict]:
        """Audit entries, newest first."""
        sql, args = "SELECT * FROM audit_log", []
        where = []
        if project is not None:
            where.append("project=?")
            args.append(project)
        if key is not None:
            where.append("key=?")
            args.append(key)
        if where:
            sql += " WHERE " + " AND ".join(where)
        with self._tx() as db:
            rows = db.execute(sql + " ORDER BY id DESC LIMIT ?", (*args, limit)).fetchall()
        return [{k: r[k] for k in ("id", "at", "project", "key", "action", "reviewer", "note", "expires")} for r in rows]

    def verify_audit(self) -> tuple[bool, int | None, int]:
        """Recompute the hash chain. Returns (intact, id of the first bad entry or None, entries checked)."""
        prev, n = GENESIS, 0
        with self._tx() as db:
            for r in db.execute("SELECT * FROM audit_log ORDER BY id").fetchall():
                fields = {k: r[k] for k in ("at", "project", "key", "action", "reviewer", "note", "expires")}
                if r["prev_hash"] != prev or r["hash"] != _entry_hash(prev, fields):
                    return False, r["id"], n
                prev, n = r["hash"], n + 1
        return True, None, n
