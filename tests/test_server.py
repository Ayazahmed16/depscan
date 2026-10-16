"""The web backend: every endpoint the frontend calls, plus the safety rules for uploads and the new feature endpoints.

Runs against the frozen known sample (tests/sample/snapshot), offline.
"""
import datetime as dt
import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from depscan import server
from depscan.pipeline import DataBundle
from depscan.server import create_app

SAMPLE = Path(__file__).parent / "sample"
REQS = (SAMPLE / "requirements.txt").read_bytes()
FUTURE = (dt.date.today() + dt.timedelta(days=20)).isoformat()      # inside the 30-day cap for critical findings


@pytest.fixture(scope="module")
def bundle():
    return DataBundle(SAMPLE / "snapshot")


@pytest.fixture()
def client(tmp_path, bundle):
    return TestClient(create_app(SAMPLE / "snapshot", tmp_path / "state" / "review.sqlite", bundle=bundle, dist=tmp_path / "nodist"))


def upload(client, *named: tuple[str, bytes]):
    return client.post("/api/scan", files=[("files", (n, d)) for n, d in named])


def zip_of(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def django_zip(prefix: str = "") -> bytes:
    app = SAMPLE / "django_app"
    return zip_of({prefix + p.relative_to(app).as_posix(): p.read_bytes() for p in app.rglob("*") if p.is_file() and "__pycache__" not in p.parts})


# ------------------------------------------------------------------ the basics
def test_health_and_meta_carry_the_disclaimer_and_snapshot_dates(client):
    h = client.get("/api/health").json()
    assert h["status"] == "ok" and set(h["snapshots"]) == {"osv", "nvd", "kev", "epss"}
    m = client.get("/api/meta").json()
    assert m["disclaimer"] == "No findings does not prove a project is secure."
    assert {"data", "matching", "trust", "exposure", "temporal", "review"} <= set(m["limitations"])
    assert "import-level" in m["limitations"]["exposure"].lower() or "import" in m["limitations"]["exposure"].lower()


def test_before_any_scan_every_read_endpoint_is_valid_and_empty(client):
    assert client.get("/api/findings").json() is None
    assert client.get("/api/graph").json() is None
    assert client.get("/api/audit").json() == []
    assert client.get("/api/watchlist").json() == []


def test_a_scan_returns_findings_and_is_remembered(client):
    r = upload(client, ("requirements.txt", REQS))
    assert r.status_code == 200
    body = r.json()
    assert body["findings"] and body["source"] == "requirements.txt"
    assert client.get("/api/findings").json()["findings"] == body["findings"]
    scores = [f["risk"]["score"] for f in body["findings"] if f["claim_status"] == "matched"]
    assert scores == sorted(scores, reverse=True)


def test_reset_clears_the_scan(client):
    upload(client, ("requirements.txt", REQS))
    assert client.post("/api/reset").json() == {"ok": True}
    assert client.get("/api/findings").json() is None


def test_unreadable_uploads_get_a_plain_message_not_a_crash(client):
    r = upload(client, ("package.json", b"{ not json"))
    assert r.status_code == 400 and "package.json" in r.text
    r = upload(client, ("notes.md", b"hello"))
    assert r.status_code == 400 and r.text


def test_too_many_or_too_large_uploads_are_refused(client, monkeypatch):
    assert upload(client, *[(f"r{i}.txt", b"requests==2.0.0\n") for i in range(server.MAX_FILES_PER_SCAN + 1)]).status_code == 400
    monkeypatch.setattr(server, "MAX_UPLOAD_BYTES", 10)
    assert upload(client, ("requirements.txt", REQS)).status_code == 413


def test_the_uploaded_file_is_never_modified(client, tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_bytes(REQS)
    before = f.read_bytes()
    upload(client, ("requirements.txt", f.read_bytes()))
    assert f.read_bytes() == before


# ------------------------------------------------------------------ evidence (C3)
def test_each_finding_carries_its_advisories_with_ranges_and_links(client):
    for f in upload(client, ("requirements.txt", REQS)).json()["findings"]:
        if f["claim_status"] != "matched":
            continue
        assert f["advisories"], f["id"]
        for a in f["advisories"]:
            assert a["id"] and a["links"][0]["url"].startswith("https://osv.dev/vulnerability/")
            assert a["affected_ranges"] or a["affected_versions_listed"]
        assert any(link["url"].startswith("https://nvd.nist.gov/vuln/detail/CVE-") for a in f["advisories"] for link in a["links"]) or not f["id"].startswith("CVE-")


# ------------------------------------------------------------------ project zip: exposure graph
def test_a_zipped_django_project_gets_an_exposure_graph(client):
    r = upload(client, ("project.zip", django_zip("myapp/")))
    assert r.status_code == 200
    body = r.json()
    assert body["graph"] and body["graph"]["limitation"]
    levels = {f["package"]: f["exposure"]["level"] for f in body["findings"] if f["exposure"]}
    assert levels.get("pyyaml") == "web" and levels.get("flask") == "none"
    assert client.get("/api/graph").json()["nodes"]


def test_a_zip_with_unsafe_paths_is_refused(client):
    for name in ("../evil.py", "a/../../evil.py", "/abs/evil.py", "C:/evil.py"):
        r = upload(client, ("p.zip", zip_of({name: b"x = 1", "requirements.txt": REQS})))
        assert r.status_code == 400 and "unsafe" in r.text, name


def test_a_bad_or_oversized_zip_is_refused(client, monkeypatch):
    assert upload(client, ("p.zip", b"not a zip")).status_code == 400
    monkeypatch.setattr(server, "MAX_UNPACKED_BYTES", 5)
    r = upload(client, ("p.zip", zip_of({"requirements.txt": REQS})))
    assert r.status_code == 400 and "expands" in r.text


def test_a_zip_only_has_its_python_and_manifest_files_unpacked(tmp_path):
    server.unpack_project(zip_of({"a/requirements.txt": b"x", "a/app.py": b"import os", "a/data.bin": b"zz", "a/node_modules/m.py": b"1",
                                  "a/.venv/lib/s.py": b"1"}), tmp_path)
    assert sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file()) == ["a/app.py", "a/requirements.txt"]


def test_project_code_in_the_zip_is_read_never_run(client, tmp_path):
    marker = tmp_path / "ran.txt"
    code = f"open(r'{marker}', 'w').write('x')\nraise SystemExit(1)\n"
    r = upload(client, ("p.zip", zip_of({"manage.py": code.encode(), "requirements.txt": REQS})))
    assert r.status_code == 200 and not marker.exists()


def test_a_zip_without_dependency_files_says_so(client):
    r = upload(client, ("p.zip", zip_of({"app.py": b"x = 1"})))
    assert r.status_code == 400 and "nothing to scan" in r.text


# ------------------------------------------------------------------ reviewer actions (X4)
def pick(scan):
    return next(f for f in scan["findings"] if f["claim_status"] == "matched")


def decide(client, key, decision="accept_risk", **kw):
    body = {"key": key, "decision": decision, "note": "reviewed by the team lead", "reviewer": "Ana", "expires": FUTURE, **kw}
    return client.post("/api/review", json=body)


def test_a_decision_is_stored_shown_beside_the_finding_and_logged(client):
    scan = upload(client, ("requirements.txt", REQS)).json()
    target = pick(scan)
    r = decide(client, target["key"])
    assert r.status_code == 200 and r.json()["reviewer"] == "Ana"
    now = client.get("/api/findings").json()
    f = next(x for x in now["findings"] if x["key"] == target["key"])
    assert f["review_status"] == "accept_risk" and f["review"]["note"] and f["risk"]["score"] == target["risk"]["score"]
    assert f["action"] == target["action"]                            # a decision never changes the recommendation
    assert now["review_summary"]["accept_risk"] == 1
    log = client.get("/api/audit").json()
    assert [e["action"] for e in log] == ["accept_risk"] and log[0]["key"] == target["key"]


def test_a_decided_finding_moves_below_the_open_ones_but_stays_listed(client):
    scan = upload(client, ("requirements.txt", REQS)).json()
    matched = [f for f in scan["findings"] if f["claim_status"] == "matched"]
    top = matched[0]
    decide(client, top["key"], "false_positive")
    after = client.get("/api/findings").json()["findings"]
    matched_after = [f for f in after if f["claim_status"] == "matched"]
    assert len(after) == len(scan["findings"])                         # nothing is deleted
    assert matched_after[-1]["key"] == top["key"] and matched_after[0]["key"] != top["key"]
    open_scores = [f["risk"]["score"] for f in matched_after if f["review_status"] == "pending"]
    assert open_scores == sorted(open_scores, reverse=True)


def test_fix_now_does_not_move_a_finding(client):
    scan = upload(client, ("requirements.txt", REQS)).json()
    top = pick(scan)
    decide(client, top["key"], "fix_now", expires=None)
    assert client.get("/api/findings").json()["findings"][0]["key"] == top["key"]


def test_revoke_puts_the_finding_back_and_keeps_the_history(client):
    top = pick(upload(client, ("requirements.txt", REQS)).json())
    decide(client, top["key"])
    r = client.post("/api/review/revoke", json={"key": top["key"], "note": "plans changed, look again", "reviewer": "Ben"})
    assert r.status_code == 200
    f = next(x for x in client.get("/api/findings").json()["findings"] if x["key"] == top["key"])
    assert f["review_status"] == "pending" and f["review"] is None
    assert [e["action"] for e in client.get("/api/audit").json()] == ["revoked", "accept_risk"]


def test_bad_review_requests_get_readable_400s(client):
    top = pick(upload(client, ("requirements.txt", REQS)).json())
    for kw, word in [({"note": "ok"}, "reason"), ({"reviewer": " "}, "reviewer"), ({"expires": None}, "expiry"),
                     ({"expires": "2020-01-01"}, "future"), ({"decision": "ignore"}, "decision")]:
        r = decide(client, top["key"], **kw)
        assert r.status_code == 400 and word in r.text.lower(), kw
    assert decide(client, "no|such|key|x").status_code == 400
    assert client.post("/api/review/revoke", json={"key": top["key"], "note": "nothing to revoke here", "reviewer": "Ben"}).status_code == 400
    assert client.get("/api/audit").json() == []                       # failures leave no trace in the log


def test_review_and_revoke_need_a_scan(client):
    assert decide(client, "k").status_code == 400
    assert client.post("/api/review/revoke", json={"key": "k", "note": "a good enough reason", "reviewer": "Ben"}).status_code == 400


def test_decisions_survive_a_reset_and_a_new_scan(client):
    top = pick(upload(client, ("requirements.txt", REQS)).json())
    decide(client, top["key"])
    client.post("/api/reset")
    again = upload(client, ("requirements.txt", REQS)).json()
    assert next(f for f in again["findings"] if f["key"] == top["key"])["review_status"] == "accept_risk"


# ------------------------------------------------------------------ adjustable weights (X5)
def test_weights_can_be_read(client):
    w = client.get("/api/config/weights").json()
    assert w["customised"] is False and w["weights"] == w["defaults"]
    assert abs(sum(w["weights"].values()) - 1) < 1e-6


def test_invalid_weights_are_refused_with_a_reason(client):
    w = client.get("/api/config/weights").json()["weights"]
    for bad, word in [({**w, "severity": 0.9}, "add up"), ({**w, "severity": -0.1, "criticality": 0.55}, "zero or more"),
                      ({k: v for k, v in w.items() if k != "exposure"}, "exactly"), ({**w, "mystery": 0.0}, "exactly")]:
        r = client.put("/api/config/weights", json={"weights": bad})
        assert r.status_code == 400 and word in r.text, bad
    assert client.get("/api/config/weights").json()["customised"] is False


def test_changing_a_weight_rescores_the_current_scan_and_can_be_undone(client):
    before = {f["key"]: f["risk"]["score"] for f in upload(client, ("requirements.txt", REQS)).json()["findings"]}
    w = client.get("/api/config/weights").json()["weights"]
    heavier = {**w, "severity": 0.0, "known_exploited": 0.5, "exploit_likelihood": 0.5, "criticality": 0.0, "fix_availability": 0.0, "exposure": 0.0}
    r = client.put("/api/config/weights", json={"weights": heavier})
    assert r.status_code == 200 and r.json()["rescored"] is True and r.json()["customised"] is True
    after = {f["key"]: f["risk"]["score"] for f in client.get("/api/findings").json()["findings"]}
    assert after.keys() == before.keys() and after != before
    r = client.delete("/api/config/weights")
    assert r.json()["customised"] is False
    assert {f["key"]: f["risk"]["score"] for f in client.get("/api/findings").json()["findings"]} == before


def test_weights_apply_to_the_next_scan_and_survive_a_restart(tmp_path, bundle):
    def app():
        return TestClient(create_app(SAMPLE / "snapshot", tmp_path / "state" / "review.sqlite", bundle=bundle, dist=tmp_path / "nodist"))

    c = app()
    w = c.get("/api/config/weights").json()["weights"]
    new = {**w, "severity": 0.1, "known_exploited": 0.4}
    assert c.put("/api/config/weights", json={"weights": new}).json()["rescored"] is False       # nothing scanned yet
    c2 = app()
    assert c2.get("/api/config/weights").json()["weights"] == new
    f = upload(c2, ("requirements.txt", REQS)).json()["findings"][0]
    assert {x["name"]: x["weight"] for x in f["risk"]["factors"] if x["name"] in new}["known_exploited"] > 0.3  # renormalised, but used
    assert (Path(__file__).parent.parent / "config" / "scoring.yaml").read_text("utf-8").count("known_exploited: 0.20") == 1  # file untouched


def test_weights_are_normalised_when_they_are_a_hair_off(client):
    w = client.get("/api/config/weights").json()["weights"]
    r = client.put("/api/config/weights", json={"weights": {**w, "severity": w["severity"] + 0.005}})
    assert r.status_code == 200 and abs(sum(r.json()["weights"].values()) - 1) < 0.001


# ------------------------------------------------------------------ temporal view and watchlist (X3)
def test_history_is_real_dated_and_never_simulated(client):
    findings = upload(client, ("requirements.txt", REQS)).json()["findings"]
    assert any(f["history"] for f in findings)
    for f in findings:
        dates = [p["date"] for p in f["history"]]
        assert dates == sorted(dates) and len(dates) == len(set(dates))
        for p in f["history"]:
            assert p["simulated"] is False and 0 <= p["risk"] <= 100
            assert p["epss"] is None or 0 <= p["epss"] <= 1


def test_the_kev_date_and_publication_appear_as_events(client):
    kev = next(f for f in upload(client, ("requirements.txt", REQS)).json()["findings"] if f["kev"])
    events = " ".join(p["event"] or "" for p in kev["history"])
    assert "added to CISA KEV" in events and "advisory published" in events
    published = next(p for p in kev["history"] if p["event"] and "published" in p["event"])
    listed = next(p for p in kev["history"] if p["event"] and "KEV" in p["event"])
    assert listed["risk"] > published["risk"]                          # being listed raised the risk on that date


def test_the_watchlist_flags_a_rising_epss_that_is_not_yet_critical(client):
    scan = upload(client, ("requirements.txt", REQS)).json()
    rows = client.get("/api/watchlist").json()
    assert rows and all(set(r) == {"key", "package", "id", "risk", "reason"} for r in rows)
    by_key = {f["key"]: f for f in scan["findings"]}
    for r in rows:
        assert by_key[r["key"]]["watch"] == r["reason"] and r["risk"] < 60 and ("EPSS rose" in r["reason"] or "added to CISA KEV" in r["reason"])
    assert not any(f["risk"]["score"] >= 60 and f["watch"] for f in scan["findings"])


# ------------------------------------------------------------------ serving the site
def test_the_built_site_is_served_with_a_fallback_for_client_routes(tmp_path, bundle):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html>depscan</html>", "utf-8")
    (dist / "assets" / "a.js").write_text("1", "utf-8")
    (tmp_path / "secret.txt").write_text("secret", "utf-8")
    c = TestClient(create_app(SAMPLE / "snapshot", tmp_path / "r.sqlite", bundle=bundle, dist=dist))
    assert "depscan" in c.get("/").text and "depscan" in c.get("/app").text and "depscan" in c.get("/app/anything").text
    assert c.get("/assets/a.js").text == "1"
    assert c.get("/api/health").json()["status"] == "ok"
    assert c.get("/api/nope").status_code == 404
    assert "secret" not in c.get("/..%2Fsecret.txt").text and "secret" not in c.get("/%2e%2e/secret.txt").text


def test_a_missing_advisory_index_is_a_clear_503(tmp_path):
    empty = tmp_path / "data"
    empty.mkdir()
    c = TestClient(create_app(empty, tmp_path / "r.sqlite", dist=tmp_path / "nodist"))
    r = upload(c, ("requirements.txt", REQS))
    assert r.status_code == 503 and "fetch_data" in r.text


def test_json_bodies_round_trip(client):
    scan = upload(client, ("requirements.txt", REQS)).json()
    json.dumps(scan)                                                    # fully serialisable, no NaN surprises
    assert "NaN" not in client.get("/api/findings").text


def test_a_zip_with_too_many_files_is_refused(client, monkeypatch):
    monkeypatch.setattr(server, "MAX_ZIP_FILES", 2)
    r = upload(client, ("p.zip", zip_of({"requirements.txt": REQS, "a.py": b"1", "b.py": b"2"})))
    assert r.status_code == 400 and "more than 2 files" in r.text
