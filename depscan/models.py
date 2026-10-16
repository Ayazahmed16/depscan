"""Plain data classes shared by parsers, matcher and scoring."""
from __future__ import annotations

from dataclasses import dataclass, field


# Match confidence, strongest first. The trust layer (phase 5) reads this ordering.
CONFIDENCE_ORDER = ["confirmed", "likely", "possible", "probable", "uncertain"]


@dataclass
class ScannerClaim:
    """A vulnerability a third-party scanner (e.g. Dependency-Check) says applies to a dependency."""
    cve: str
    severity: str | None = None       # the scanner's own label, e.g. HIGH
    cvss: float | None = None         # the scanner's own base score
    confidence: str | None = None     # how sure the scanner was about the package identity (HIGHEST..LOW)
    source: str = "scan report"


@dataclass
class Dependency:
    name: str
    ecosystem: str                    # "PyPI" or "npm"
    spec: str = ""                    # what the file said, e.g. "==1.2.3" or "^4.17.0"
    version: str | None = None        # exact version if the file pins one
    lower_bound: str | None = None    # lowest version the spec allows (used for probable matches)
    direct: bool = True
    scope: str = "runtime"            # "runtime" or "dev"
    source: str = ""                  # file the dependency came from
    line: int | None = None
    claims: list[ScannerClaim] = field(default_factory=list)
    resolution: str = "range"         # pin | lockfile | range: how `version` was learned
    newest: str | None = None         # newest registry release satisfying the range (step 2)
    registry_status: str | None = None  # resolved | failed | None (not attempted)

    @property
    def exact(self) -> bool:
        return self.version is not None

    @property
    def candidate(self) -> str | None:
        """The version used for display and fallbacks: pinned, else newest resolved, else the lower bound."""
        return self.version or self.newest or self.lower_bound


@dataclass
class ParseResult:
    dependencies: list[Dependency]
    source: str
    kind: str                         # requirements.txt / package.json / package-lock.json / dependency-check
    warnings: list[str] = field(default_factory=list)  # things we could not read; shown to the user


@dataclass
class SourceVerdict:
    """What ONE advisory record (e.g. the GHSA one or the PYSEC one) says about a version."""
    advisory_id: str
    affected: bool | None             # True / False, or None if the record cannot tell us
    reason: str                       # human-readable, goes into the evidence
    fixed_in: str | None = None       # the fix that follows the matched interval, if any


@dataclass
class Match:
    """A dependency matched to a vulnerability, before scoring."""
    id: str                           # primary id, a CVE when one exists
    aliases: list[str]
    dependency: Dependency
    confidence: str                   # confirmed | likely | possible | probable | uncertain
    evidence: list[str]
    verdicts: list[SourceVerdict]
    advisories: list[dict]            # the raw (compact) OSV records behind this match
    fixed_versions: list[str] = field(default_factory=list)
    scanner_only: bool = False        # only a scan report claimed it, OSV data did not confirm
    contradicted: bool = False        # OSV data says the version is NOT affected
    version: str | None = None        # the version that was found affected (used for fixes and display)
