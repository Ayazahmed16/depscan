"""Phase 3 tests: the whole pipeline and the report, on the synthetic data directory in conftest.py."""
import json

from depscan.pipeline import DataBundle, scan_bytes
from depscan.report import NOTICE, render_html, render_markdown

REQS = b"alpha==1.0\nbeta==2.0\ngamma==1.0\ndelta==1.0\n"


def scan(data_dir, content=REQS, name="requirements.txt"):
    return scan_bytes(name, content, DataBundle(data_dir))


def test_known_sample_ranking_and_fields(data_dir):
    r = scan(data_dir)
    assert r["dependencies_read"] == 4
    ids = [f["id"] for f in r["findings"]]
    # gamma has no advisory and delta's range excludes 1.0: both must be absent
    assert ids == ["CVE-2030-0001", "CVE-2030-0002"]
    alpha, beta = r["findings"]
    assert alpha["package"] == "alpha" and alpha["cvss"] == 9.8 and alpha["kev"] is True
    assert alpha["epss"] == 0.9 and alpha["fixed_version"] == "1.5" and alpha["major_bump"] is False
    assert beta["cvss"] == 5.3 and beta["fixed_version"] == "3.0" and beta["major_bump"] is True
    assert alpha["risk"]["score"] > beta["risk"]["score"]
    assert alpha["action"] == "fix_now" and beta["action"] in ("monitor", "no_action")
    assert alpha["match"]["confidence"] == "exact" and alpha["match"]["evidence"]
    assert r["snapshots"]["kev"] == "2030-03-01"


def test_findings_never_contain_fabricated_trust_yet(data_dir):
    assert "trust" not in scan(data_dir)["findings"][0]  # added by phase 5, no placeholder numbers


def test_range_spec_is_probable_and_says_so(data_dir):
    r = scan(data_dir, b"alpha>=1.0\n")
    f = r["findings"][0]
    assert f["match"]["confidence"] == "probable" and "pin or lock" in f["recommendation"]


def test_package_actions_give_one_upgrade_target(data_dir):
    r = scan(data_dir)
    acts = {a["package"]: a for a in r["package_actions"]}
    assert acts["alpha"]["target_version"] == "1.5" and acts["alpha"]["clears"] == 1
    assert acts["beta"]["target_version"] == "3.0"


def test_clean_manifest_reports_no_findings_with_the_notice(data_dir):
    r = scan(data_dir, b"gamma==1.0\n")
    assert r["findings"] == []
    assert NOTICE in render_markdown(r) and NOTICE in render_html(r)


def test_input_file_is_never_modified(data_dir, tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_bytes(REQS)
    before = (f.read_bytes(), f.stat().st_mtime_ns)
    from depscan.__main__ import main
    assert main(["scan", str(f), "--data-dir", str(data_dir), "--out", str(tmp_path / "out.json")]) == 0
    assert (f.read_bytes(), f.stat().st_mtime_ns) == before
    assert json.loads((tmp_path / "out.json").read_text())["findings"]


def test_reports_contain_required_content_and_escape_html(data_dir):
    r = scan(data_dir)
    r["findings"][0]["summary"] = "<script>alert(1)</script>"
    md, page = render_markdown(r), render_html(r)
    for text in (md, page):
        assert NOTICE in text and "CVE-2030-0001" in text and "Recommendation" in text
        assert "Limitations" in text and "2030-03-01" in text
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page


def test_cli_reports_missing_data_clearly(tmp_path, capsys):
    from depscan.__main__ import main
    f = tmp_path / "requirements.txt"
    f.write_text("alpha==1.0\n")
    assert main(["scan", str(f), "--data-dir", str(tmp_path / "nope")]) == 2
    assert "fetch_data.py" in capsys.readouterr().err
