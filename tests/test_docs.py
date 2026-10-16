"""The docs the project ships with: required notice, working links, and a demo script that fits its time limit."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
NOTICE = "No findings does not prove a project is secure."
DOCS = ["README.md", "docs/ARCHITECTURE.md", "docs/DEMO.md", "docs/BENCHMARK.md", "docs/SCORING.md", "docs/CONTRACT.md",
        "docs/EXPOSURE.md", "docs/REVIEW.md", "docs/CI.md", "vscode-extension/README.md"]


@pytest.mark.parametrize("name", ["README.md", "docs/ARCHITECTURE.md", "docs/DEMO.md", "docs/SCORING.md", "vscode-extension/README.md"])
def test_the_required_notice_is_in_the_main_docs(name):
    assert NOTICE in (ROOT / name).read_text("utf-8")


@pytest.mark.parametrize("name", DOCS)
def test_relative_links_point_at_real_files(name):
    text = (ROOT / name).read_text("utf-8")
    for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", text):
        if re.match(r"^[a-z]+:", target):
            continue
        assert (ROOT / name).parent.joinpath(target).resolve().exists(), f"{name} links to missing {target}"


def test_the_demo_script_fits_in_two_minutes():
    text = (ROOT / "docs" / "DEMO.md").read_text("utf-8")
    rows = [line for line in text.splitlines() if re.match(r"\| \d:\d\d \|", line)]
    spoken = sum(len(line.split("|")[3].split()) for line in rows)
    assert 6 <= len(rows) <= 10 and spoken <= 270, f"{spoken} spoken words is about {spoken / 150 * 60:.0f} s at 150 words a minute"
    last = rows[-1].split("|")[1].strip()
    minutes, seconds = last.split(":")
    assert int(minutes) * 60 + int(seconds) < 120                       # the last cue starts before the two-minute mark
    assert NOTICE in rows[-1]


def test_every_file_the_demo_and_readme_tell_you_to_upload_exists():
    for name in ("mock/requirements.txt", "mock/django_app.zip", "tests/sample/requirements.txt", "tests/sample/django_app/manage.py"):
        assert (ROOT / name).is_file(), name


def test_the_benchmark_doc_says_the_labels_are_unverified():
    text = (ROOT / "docs" / "BENCHMARK.md").read_text("utf-8").lower()
    assert "needs manual verification" in text and "provisional" in text


def test_the_readme_does_not_claim_features_that_are_not_built():
    text = (ROOT / "README.md").read_text("utf-8")
    assert "planned phases" not in text and "not built yet" not in text and "phase 11" not in text


def test_the_ci_doc_matches_the_workflows_and_exit_codes():
    import yaml
    doc = (ROOT / "docs" / "CI.md").read_text("utf-8")
    assert "--fail-on" in doc and NOTICE in doc and "have not been run on GitHub" in doc
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text("utf-8"))
    assert {"python", "gate", "frontend"} <= set(ci["jobs"])
    for fixture in ("py-web-old", "clean-current"):                       # the fixtures the gate job scans must exist
        assert (ROOT / "benchmark" / "fixtures" / fixture).is_dir() and fixture in doc
    example = yaml.safe_load((ROOT / "docs" / "ci" / "depscan-github-workflow.yml").read_text("utf-8"))
    assert "depscan" in example["jobs"]
