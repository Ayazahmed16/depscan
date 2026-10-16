"""Entry point: pick the right parser from a file's name and content."""
from __future__ import annotations

import json

from ..models import ParseResult
from .depcheck import parse_depcheck
from .package_json import parse_package_json, parse_package_lock
from .requirements import parse_requirements


class UnsupportedFile(ValueError):
    pass


def parse_file(name: str, content: bytes) -> ParseResult:
    """Parse an uploaded dependency file or scan report. `content` is only read, never saved back."""
    text = content.decode("utf-8-sig", errors="replace")
    lowered = name.lower()
    if lowered.endswith(".json"):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise UnsupportedFile(f"{name} is not valid JSON ({e.msg})") from e
        if not isinstance(doc, dict):
            raise UnsupportedFile(f"{name}: expected a JSON object")
        if "dependencies" in doc and isinstance(doc["dependencies"], list):
            return parse_depcheck(text, name)
        if "lockfileVersion" in doc or "packages" in doc:
            return parse_package_lock(text, name)
        if any(k in doc for k in ("dependencies", "devDependencies", "optionalDependencies", "name")):
            return parse_package_json(text, name)
        raise UnsupportedFile(f"{name}: not a package.json, package-lock.json or Dependency-Check report")
    if lowered.endswith(".txt"):
        return parse_requirements(text, name)
    raise UnsupportedFile(f"{name}: supported files are requirements.txt, package.json, package-lock.json and Dependency-Check JSON")
