"""The web backend: the same pipeline as the command line, behind the endpoints frontend/src/lib/api.ts calls.

Local, single-user tool. It reads what is uploaded and never installs, runs or changes it:
  * dependency files are parsed as text;
  * a zip of a Django project is unpacked into a temporary folder (only .py files and the known manifests, with
    zip-slip, size and count limits) and read with `ast`.
The last scan is kept in memory together with that read-only copy of the upload, so changing a weight can re-score it.
The copy is deleted on reset, on the next scan, and at shutdown. Reviewer decisions are kept in the review database
and survive a reset.
"""
from __future__ import annotations

import copy
import io
import json
import math
import shutil
import tempfile
import threading
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path, PurePosixPath
from typing import Annotated

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__
from .data.feeds import snapshot_dates
from .graph import LIMITATION
from .graph.modules import SKIP_DIRS
from .pipeline import DEFAULT_DATA_DIR, DEFAULT_REVIEW_DB, KNOWN_FILES, DataBundle, apply_reviews, collect_files, order_findings, scan_files
from .registry import Registry
from .review import ReviewError, ReviewStore
from .scoring.config import load_config

DEFAULT_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"

MAX_UPLOAD_BYTES = 25 * 1024 * 1024       # per request
MAX_UNPACKED_BYTES = 100 * 1024 * 1024    # what a zip may expand to
MAX_ZIP_FILES = 20_000
MAX_FILES_PER_SCAN = 20

DISCLAIMER = "No findings does not prove a project is secure."
LIMITATIONS = {
    "data": "Findings come from cached snapshots (OSV, NVD, CISA KEV, FIRST EPSS). A vulnerability published after the snapshot date is not covered.",
    "matching": "A version range (as opposed to a pinned or locked version) can only be bounded, so those matches carry a lower confidence.",
    "trust": "The trust score is a heuristic: its signals and points are reasoned, not fitted to data.",
    "exposure": LIMITATION,
    "temporal": "History is limited to dates the sources provide: advisory published/last modified, KEV date added, and the cached EPSS snapshots. Nothing is interpolated or simulated.",
    "review": "Reviewer names are typed in, not authenticated. The audit log is tamper-evident, not tamper-proof.",
}


class ReviewBody(BaseModel):
    key: str
    decision: str
    note: str
    reviewer: str
    expires: str | None = None


class RevokeBody(BaseModel):
    key: str
    note: str
    reviewer: str


class WeightsBody(BaseModel):
    weights: dict[str, float]


def _bad(message: str, status: int = 400):
    return HTTPException(status_code=status, detail=message)


def checked_weights(given: dict, current: dict) -> dict[str, float]:
    """Validate weights a person submits: the same factors as today, none negative, a total of 1 (within 0.01, then normalised)."""
    if set(given) != set(current):
        raise ValueError(f"weights must be given for exactly these factors: {', '.join(current)}")
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0 for v in given.values()):
        raise ValueError("weights must be numbers that are zero or more")
    total = sum(given.values())
    if abs(total - 1.0) > 0.01:
        raise ValueError(f"weights must add up to 1 (they add up to {total:.3f})")
    return {k: round(v / total, 4) for k, v in given.items()}


def unpack_project(data: bytes, dest: Path) -> None:
    """Extract only the files the scan reads (.py and known manifests) from a zip, refusing anything unsafe."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise _bad("that file is not a valid zip") from None
    infos = zf.infolist()
    if len(infos) > MAX_ZIP_FILES:
        raise _bad(f"the zip holds more than {MAX_ZIP_FILES} files")
    if sum(i.file_size for i in infos) > MAX_UNPACKED_BYTES:
        raise _bad(f"the zip expands to more than {MAX_UNPACKED_BYTES // (1024 * 1024)} MB")
    root = dest.resolve()
    for info in infos:
        if info.is_dir():
            continue
        parts = PurePosixPath(info.filename.replace("\\", "/")).parts
        if info.filename.startswith(("/", "\\")) or ".." in parts or (parts and ":" in parts[0]):
            raise _bad(f"unsafe path in the zip: {info.filename!r}")
        if any(p in SKIP_DIRS or p.endswith(".egg-info") for p in parts[:-1]):
            continue
        if not (parts[-1].endswith(".py") or parts[-1] in KNOWN_FILES):
            continue
        target = (root.joinpath(*parts)).resolve()
        if root not in target.parents:
            raise _bad(f"unsafe path in the zip: {info.filename!r}")
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as out:
            shutil.copyfileobj(src, out)


def _shallowest(root: Path, names: set[str]) -> Path | None:
    """The folder closest to the root that holds one of `names`."""
    hits = [p.parent for n in names for p in root.rglob(n)]
    return min(hits, key=lambda p: len(p.relative_to(root).parts)) if hits else None


def create_app(data_dir: Path = DEFAULT_DATA_DIR, review_db: Path = DEFAULT_REVIEW_DB, *, offline: bool = False,
               dist: Path = DEFAULT_DIST, bundle: DataBundle | None = None) -> FastAPI:
    state: dict = {"bundle": bundle, "scan": None, "inputs": None, "tmp": None}
    lock = threading.Lock()
    defaults = load_config()
    cfg = copy.deepcopy(defaults)
    weights_file = Path(review_db).parent / "weights.json"

    def drop_inputs() -> None:
        if state["tmp"]:
            shutil.rmtree(state["tmp"], ignore_errors=True)
        state["tmp"] = state["inputs"] = None

    @asynccontextmanager
    async def lifespan(_app):
        yield
        drop_inputs()

    app = FastAPI(title="depscan", version=__version__, docs_url=None, redoc_url=None, lifespan=lifespan)

    try:                                         # weights a person set earlier; the config file itself is never written
        cfg["risk"]["weights"] = checked_weights(json.loads(weights_file.read_text("utf-8"))["weights"], defaults["risk"]["weights"])
    except (OSError, ValueError, KeyError, TypeError):
        pass

    def get_bundle() -> DataBundle:
        if state["bundle"] is None:
            try:
                state["bundle"] = DataBundle(data_dir, Registry(data_dir, offline=offline), osv_api=True, offline=offline)
            except FileNotFoundError as e:
                raise _bad(str(e), 503) from None
        return state["bundle"]

    def store() -> ReviewStore:
        return ReviewStore(review_db)

    def run_scan(named, project_dir) -> dict:
        result = scan_files(named, get_bundle(), cfg, review_store=store(), project_dir=project_dir)
        state["scan"] = result
        return result

    def weights_view(rescored: bool | None = None) -> dict:
        out = {"weights": cfg["risk"]["weights"], "defaults": defaults["risk"]["weights"],
               "customised": cfg["risk"]["weights"] != defaults["risk"]["weights"]}
        if rescored is not None:
            out["rescored"] = rescored
        return out

    def apply_weights(new: dict) -> dict:
        """Use new weights, remember them, and re-score the current scan from its stored copy of the upload."""
        with lock:
            cfg["risk"]["weights"] = new
            try:
                weights_file.parent.mkdir(parents=True, exist_ok=True)
                if new == defaults["risk"]["weights"]:
                    weights_file.unlink(missing_ok=True)
                else:
                    weights_file.write_text(json.dumps({"weights": new}, indent=2), "utf-8")
            except OSError:
                pass                             # the weights still apply for this run
            rescored = bool(state["inputs"])
            if rescored:
                run_scan(*state["inputs"])
        return weights_view(rescored)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": __version__, "snapshots": snapshot_dates(data_dir)}

    @app.get("/api/meta")
    def meta():
        return {"version": __version__, "disclaimer": DISCLAIMER, "snapshots": snapshot_dates(data_dir),
                "limitations": LIMITATIONS, "stale_days": cfg["data"]["stale_days"]}

    @app.get("/api/findings")
    def findings():
        return state["scan"]

    @app.get("/api/graph")
    def graph():
        return state["scan"]["graph"] if state["scan"] else None

    @app.get("/api/watchlist")
    def watchlist():
        scan_ = state["scan"]
        rows = [f for f in scan_["findings"] if f["watch"]] if scan_ else []
        return [{"key": f["key"], "package": f["package"], "id": f["id"], "risk": f["risk"]["score"], "reason": f["watch"]} for f in rows]

    @app.get("/api/config/weights")
    def get_weights():
        return weights_view()

    @app.put("/api/config/weights")
    def put_weights(body: WeightsBody):
        try:
            new = checked_weights(body.weights, defaults["risk"]["weights"])
        except ValueError as e:
            raise _bad(str(e)) from None
        return apply_weights(new)

    @app.delete("/api/config/weights")
    def reset_weights():
        return apply_weights(copy.deepcopy(defaults["risk"]["weights"]))

    @app.post("/api/scan")
    def scan(files: Annotated[list[UploadFile], File()]):
        if not files or len(files) > MAX_FILES_PER_SCAN:
            raise _bad(f"upload between 1 and {MAX_FILES_PER_SCAN} files")
        uploads: list[tuple[str, bytes]] = []
        total = 0
        for f in files:
            data = f.file.read(MAX_UPLOAD_BYTES + 1)
            total += len(data)
            if total > MAX_UPLOAD_BYTES:
                raise _bad(f"upload is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB", 413)
            uploads.append((Path((f.filename or "upload").replace("\\", "/")).name, data))
        with lock:
            get_bundle()
            drop_inputs()
            tmp = Path(tempfile.mkdtemp(prefix="depscan-"))
            try:
                project_dir, named = None, []
                for name, data in uploads:
                    if name.lower().endswith(".zip"):
                        unpack = tmp / f"zip{len(named)}"
                        unpack.mkdir()
                        unpack_project(data, unpack)
                        manifests = _shallowest(unpack, set(KNOWN_FILES))
                        project_dir = project_dir or _shallowest(unpack, {"manage.py"})
                        named += collect_files([manifests]) if manifests else []
                    else:
                        named.append((name, data))
                if not named:
                    raise _bad("nothing to scan: no dependency file found (requirements.txt, package.json, a lock file, go.mod or a scan report)")
                try:
                    result = run_scan(named, project_dir)
                except ValueError as e:          # an unreadable or unrecognised file
                    raise _bad(str(e)) from None
            except BaseException:
                shutil.rmtree(tmp, ignore_errors=True)
                raise
            state["tmp"], state["inputs"] = tmp, (named, project_dir)
        return result

    @app.post("/api/reset")
    def reset():
        with lock:
            state["scan"] = None
            drop_inputs()
        return {"ok": True}

    @app.get("/api/audit")
    def audit():
        return store().audit(limit=500) if Path(review_db).exists() else []

    def refresh_reviews(scan_: dict) -> None:
        scan_["review_summary"] = apply_reviews(scan_["findings"], store(), scan_["project"])
        order_findings(scan_["findings"])          # a decided finding moves below the open ones; scores are untouched

    @app.post("/api/review")
    def review(body: ReviewBody):
        scan_ = state["scan"]
        finding = next((f for f in scan_["findings"] if f["key"] == body.key), None) if scan_ else None
        if finding is None:
            raise _bad("no finding with that key in the current scan")
        try:
            record = store().record(scan_["project"], body.key, body.decision, body.note, body.reviewer, body.expires,
                                    cfg=cfg, risk_score=finding["risk"]["score"])
        except ReviewError as e:
            raise _bad(str(e)) from None
        refresh_reviews(scan_)
        return record

    @app.post("/api/review/revoke")
    def revoke(body: RevokeBody):
        scan_ = state["scan"]
        if scan_ is None:
            raise _bad("there is no scan to revoke a decision in")
        try:
            store().revoke(scan_["project"], body.key, body.note, body.reviewer, cfg=cfg)
        except ReviewError as e:
            raise _bad(str(e)) from None
        refresh_reviews(scan_)
        return {"ok": True}

    @app.exception_handler(HTTPException)
    async def plain_errors(_request, exc: HTTPException):
        return PlainTextResponse(str(exc.detail), status_code=exc.status_code)   # api.ts shows the body as the message

    # The built frontend: the landing page (/) and the console (/app) are one single-page app.
    if (dist / "index.html").is_file():
        if (dist / "assets").is_dir():
            app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{path:path}")
        def spa(path: str):
            if path.startswith("api/"):
                raise _bad("not found", 404)
            candidate = (dist / path).resolve()
            if path and dist.resolve() in candidate.parents and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(dist / "index.html")

    return app
