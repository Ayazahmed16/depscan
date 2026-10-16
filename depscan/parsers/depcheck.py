"""OWASP Dependency-Check JSON report parser.

ASSUMPTION (unverified): the JSON layout below follows the documented report model
(`dependencies[]`, each with package identifiers and `vulnerabilities[]`). We could not
confirm the exact JSON key names against a real report, so this parser accepts both the
flat form (`packages`, `vulnerabilityIds`) and the nested XSD form (`identifiers.package`).
Replace tests/fixtures/depcheck-sample.json with a real report to confirm.

We read each dependency's package URL (pkg:pypi/..., pkg:npm/...) to know the ecosystem and
version, and keep the scanner's CVE list as *claims*. The matcher then checks each claim
against OSV ranges, which is how stale or uncertain scanner matches get flagged.
"""
from __future__ import annotations

import json
import re
from urllib.parse import unquote

from ..matcher.versions import normalize_pypi_name
from ..models import Dependency, ParseResult, ScannerClaim

_PURL = re.compile(r"^pkg:(?P<type>[a-z]+)/(?P<name>[^@]+)@(?P<version>[^?#]+)")
_ECOSYSTEM = {"pypi": "PyPI", "npm": "npm"}


def _identifiers(dep: dict) -> list[dict]:
    flat = dep.get("packages")
    if isinstance(flat, list):
        return flat
    nested = (dep.get("identifiers") or {}).get("package")
    return nested if isinstance(nested, list) else []


def _vulnerabilities(dep: dict) -> list[dict]:
    flat = dep.get("vulnerabilities")
    if isinstance(flat, list):
        return flat
    nested = (flat or {}).get("vulnerability") if isinstance(flat, dict) else None
    return nested if isinstance(nested, list) else []


def _cvss(vuln: dict) -> float | None:
    for key in ("cvssv3", "cvssV3", "cvssv2", "cvssV2"):
        block = vuln.get(key)
        if isinstance(block, dict):
            score = block.get("baseScore", block.get("score"))
            if isinstance(score, (int, float)):
                return float(score)
    return None


def parse_depcheck(text: str, source: str = "dependency-check-report.json") -> ParseResult:
    doc = json.loads(text)
    deps: list[Dependency] = []
    warnings: list[str] = []
    for entry in doc.get("dependencies", []):
        purl = None
        for ident in _identifiers(entry):
            m = _PURL.match(str(ident.get("id", "")))
            if m and m["type"] in _ECOSYSTEM:
                purl = (m, ident.get("confidence"))
                break
        vulns = _vulnerabilities(entry)
        if purl is None:
            if vulns:
                warnings.append(f"{entry.get('fileName', '?')}: {len(vulns)} claimed vulnerabilities but no PyPI/npm package id; skipped")
            continue
        m, id_confidence = purl
        eco = _ECOSYSTEM[m["type"]]
        name = unquote(m["name"]).lower()
        name = normalize_pypi_name(name) if eco == "PyPI" else name
        version = unquote(m["version"])
        claims = []
        for v in vulns:
            cve = str(v.get("name", ""))
            if cve:
                claims.append(ScannerClaim(
                    cve=cve, severity=(v.get("severity") or "").upper() or None, cvss=_cvss(v),
                    confidence=id_confidence, source=str(v.get("source", "scan report")),
                ))
        deps.append(Dependency(
            name=name, ecosystem=eco, spec=f"=={version}", version=version, lower_bound=version,
            direct=True, scope="runtime", source=source, claims=claims,
        ))
    if deps:
        warnings.append("scan reports do not say whether a dependency is direct or dev-only; assumed direct and runtime")
    return ParseResult(deps, source, "dependency-check", warnings)
