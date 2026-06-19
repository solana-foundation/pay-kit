# examples/playground_api/docs.py
"""Docs server — port of the TypeScript playground's `docs.ts`.

Serves the generated SDK reference markdown under the repo's ``docs/api/`` for
the playground's Docs / ApiReference pages. No payment, no dependencies beyond
the filesystem; entirely separate from the gated routes. Degrades gracefully
when the docs have not been generated yet.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

# docs/api lives at the repo root: playground_api -> examples -> python -> root.
DOCS_ROOT = Path(__file__).resolve().parents[3] / "docs" / "api"

LANGS = ("typescript", "rust", "go", "python", "ruby", "php", "lua", "kotlin", "swift")


def _build_tree(abs_dir: Path, rel_dir: str = "") -> list[dict[str, Any]]:
    """A folders-first, alpha-sorted tree of the ``.md`` files under ``abs_dir``."""
    nodes: list[dict[str, Any]] = []
    for entry in abs_dir.iterdir():
        if entry.name.startswith(".") or entry.name == "node_modules":
            continue
        rel_path = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
        if entry.is_dir():
            nodes.append(
                {"name": entry.name, "path": rel_path, "type": "dir", "children": _build_tree(entry, rel_path)}
            )
        elif entry.is_file() and entry.name.endswith(".md"):
            nodes.append({"name": entry.name, "path": rel_path, "type": "file"})
    nodes.sort(key=lambda n: (n["type"] != "dir", n["name"]))
    return nodes


def _safe_join(root: Path, rel: str) -> Path | None:
    """Resolve ``rel`` under ``root``, or ``None`` if it escapes the root."""
    joined = (root / rel).resolve()
    try:
        joined.relative_to(root.resolve())
    except ValueError:
        return None
    return joined


def register_docs(app: Any) -> None:
    """Mount the unpaid docs routes (mirrors `registerDocs` in docs.ts)."""
    from fastapi import Request
    from fastapi.responses import JSONResponse, PlainTextResponse

    @app.get("/api/v1/docs")
    async def docs_index() -> dict[str, Any]:  # pyright: ignore[reportUnusedFunction]
        available = {lang: (DOCS_ROOT / lang / "README.md").is_file() for lang in LANGS}
        return {"root": str(DOCS_ROOT), "available": available}

    @app.get("/api/v1/docs/{lang}/tree")
    async def docs_tree(lang: str) -> JSONResponse:  # pyright: ignore[reportUnusedFunction]
        if lang not in LANGS:
            return JSONResponse({"error": "unknown_lang"}, status_code=404)
        root = DOCS_ROOT / lang
        if not root.is_dir():
            return JSONResponse({"error": "not_generated"}, status_code=404)
        try:
            return JSONResponse({"lang": lang, "tree": _build_tree(root)})
        except OSError as err:
            return JSONResponse({"error": "tree_failed", "detail": str(err)}, status_code=500)

    @app.get("/api/v1/docs/{lang}/file")
    async def docs_file(lang: str, request: Request):  # pyright: ignore[reportUnusedFunction]
        if lang not in LANGS:
            return JSONResponse({"error": "unknown_lang"}, status_code=404)
        abs_path = _safe_join(DOCS_ROOT / lang, request.query_params.get("path", "README.md"))
        if abs_path is None:
            return JSONResponse({"error": "unsafe_path"}, status_code=400)
        if abs_path.suffix != ".md":
            return JSONResponse({"error": "not_markdown"}, status_code=400)
        try:
            return PlainTextResponse(abs_path.read_text(encoding="utf-8"), media_type="text/markdown")
        except OSError as err:
            return JSONResponse({"error": "not_found", "detail": str(err)}, status_code=404)
