"""Temporal view: a per-finding timeline built only from dates the data sources really give us, and a watchlist.

Real dates only:
  * advisory published / last modified (OSV),
  * the day the CVE was added to CISA KEV,
  * every cached EPSS file (a handful of dated snapshots, not a daily series).
Nothing is interpolated or simulated, so every point has `simulated: false`.

Each point's risk score is recomputed with only what was known on that date (the EPSS value of the newest file on or
before it, KEV only once listed). The factors that have no history here (severity, fix, exposure, how the package is
used) are held at today's values. Between two points the risk is not guessed.
"""
from __future__ import annotations

import datetime as dt

from .models import Match
from .scoring.risk import compute_risk, cve_ids


def _day(stamp: str | None) -> str | None:
    return stamp[:10] if stamp and len(stamp) >= 10 else None


def build_history(match: Match, *, nvd, kev, epss_series: dict[str, list[tuple[str, float]]], fixed_version, major_bump,
                  exposed, cfg: dict) -> list[dict]:
    """Dated points, oldest first. Empty when the data holds no dates for this finding."""
    cves = cve_ids(match)
    events: dict[str, list[str]] = {}

    def add(day: str | None, text: str) -> None:
        if day:
            events.setdefault(day, []).append(text)

    published = [d for d in (_day(a.get("published")) for a in match.advisories) if d]
    modified = [d for d in (_day(a.get("modified")) for a in match.advisories) if d]
    if published:
        add(min(published), "advisory published")
    kev_entry = next((kev[c] for c in cves if c in kev), None)
    kev_day = _day(kev_entry["dateAdded"]) if kev_entry else None
    add(kev_day, "added to CISA KEV")
    series: list[tuple[str, float]] = sorted({(d, v) for c in cves for d, v in epss_series.get(c, [])})
    for day, _ in series:
        events.setdefault(day, [])          # an EPSS snapshot date is a point even with no event to name
    if modified and max(modified) != min(published, default=None):
        add(max(modified), "advisory last modified")

    points = []
    for day in sorted(events):
        known = [(d, v) for d, v in series if d <= day]
        # the newest EPSS value on or before this date; per-CVE series merge by taking the highest value of that date
        epss_now = max((v for d, v in known if d == known[-1][0]), default=None) if known else None
        kev_now = {c: kev[c] for c in cves if c in kev and kev_day and kev_day <= day}
        risk = compute_risk(match, nvd=nvd, kev=kev_now, epss={cves[0]: (epss_now, 0.0)} if epss_now is not None and cves else {},
                            fixed_version=fixed_version, major_bump=major_bump, cfg=cfg, exposed=exposed)
        points.append({
            "date": day,
            "risk": risk["score"],
            "epss": epss_now,
            "event": "; ".join(events[day]) or None,
            "simulated": False,
        })
    return points


def watch_reason(history: list[dict], risk_score: float, kev_day: str | None, as_of: dt.date, cfg: dict) -> str | None:
    """Why this finding is on the watchlist, or None. Only findings not already in the critical tier qualify."""
    rules = cfg["temporal"]["watch"]
    if risk_score >= cfg["risk"]["tiers"]["critical"]:
        return None
    if kev_day:
        try:
            age = (as_of - dt.date.fromisoformat(kev_day)).days
        except ValueError:
            age = None
        if age is not None and 0 <= age <= rules["kev_recent_days"]:
            return f"added to CISA KEV on {kev_day}, {age} days before the data snapshot; not yet in the critical tier"
    scored = [(p["date"], p["epss"]) for p in history if p["epss"] is not None]
    if len(scored) >= rules["epss_min_points"]:
        (d0, e0), (d1, e1) = scored[0], scored[-1]
        rose = e1 - e0
        if rose >= rules["epss_rise_abs"] or (e0 >= rules["epss_floor"] and e1 >= e0 * rules["epss_rise_ratio"]):
            return (f"EPSS rose from {e0 * 100:.1f}% ({d0}) to {e1 * 100:.1f}% ({d1}) across the cached snapshots; "
                    f"not yet in the critical tier")
    return None
