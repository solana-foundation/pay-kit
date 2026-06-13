# examples/playground_api/docs.py
"""Serves the generated API reference markdown from ``<repo-root>/docs/api``,
with a path-escape guard. Override the root with the ``DOCS_ROOT`` env var when
running the app outside the repository checkout.

Mirrors the Go example's ``docs.go``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from .utils import json_error

if TYPE_CHECKING:
    from .app import AppState

# doc_langs are the languages the playground docs browser knows about.
DOC_LANGS = ["typescript", "rust", "go", "python", "ruby", "php", "lua", "kotlin", "swift"]

# Maps a docs language to its justfile recipe suffix.
_DOCS_RECIPE_SLUG = {
    "typescript": "ts",
    "rust": "rs",
    "python": "py",
    "ruby": "rb",
    "kotlin": "kt",
}


def docs_recipe_slug(lang: str) -> str:
    """Return the justfile recipe suffix for a docs language."""
    return _DOCS_RECIPE_SLUG.get(lang, lang)


def is_doc_lang(lang: str) -> bool:
    """Report whether ``lang`` is a known docs language."""
    return lang in DOC_LANGS


def docs_root(repo_root: str | None) -> str:
    """Resolve the generated-docs directory."""
    override = os.getenv("DOCS_ROOT")
    if override:
        return override
    if not repo_root:
        return ""
    return str(Path(repo_root) / "docs" / "api")


def find_repo_root() -> str | None:
    """Walk up from the working directory to the repository root (the directory
    containing ``.git`` or the top-level ``justfile``). Returns ``None`` when no
    marker is found.
    """
    try:
        directory = Path.cwd()
    except OSError:
        return None
    while True:
        if (directory / ".git").exists() or (directory / "justfile").exists():
            return str(directory)
        parent = directory.parent
        if parent == directory:
            return None
        directory = parent


def _safe_join(root: str, rel: str) -> str | None:
    """Join ``rel`` onto ``root`` and reject any path escaping the root."""
    root_path = Path(root).resolve()
    joined = (root_path / rel).resolve()
    try:
        joined.relative_to(root_path)
    except ValueError:
        return None
    return str(joined)


def _build_docs_tree(abs_dir: str, rel_dir: str) -> list[dict[str, Any]]:
    """Walk the language docs directory: folders first, then markdown files,
    both alphabetical, skipping dotfiles and ``node_modules``.
    """
    nodes: list[dict[str, Any]] = []
    for entry in os.scandir(abs_dir):
        name = entry.name
        if name.startswith(".") or name == "node_modules":
            continue
        rel_path = f"{rel_dir}/{name}" if rel_dir else name
        if entry.is_dir():
            children = _build_docs_tree(entry.path, rel_path)
            nodes.append({"name": name, "path": rel_path, "type": "dir", "children": children})
        elif name.endswith(".md"):
            nodes.append({"name": name, "path": rel_path, "type": "file"})
    nodes.sort(key=lambda node: (node["type"] != "dir", node["name"]))
    return nodes


def build_docs_router(state: AppState) -> APIRouter:
    """Build the generated-docs browsing endpoints.

    Routes (all free):
      - GET /api/v1/docs: per-language availability map
      - GET /api/v1/docs/{lang}/tree: the docs file tree
      - GET /api/v1/docs/{lang}/file?path=: one markdown file
    """
    router = APIRouter()
    root = docs_root(state.repo_root)

    @router.get("/api/v1/docs")
    async def docs_index() -> JSONResponse:
        available = {lang: (Path(root) / lang / "README.md").exists() if root else False for lang in DOC_LANGS}
        return JSONResponse({"root": root, "available": available})

    @router.get("/api/v1/docs/{lang}/tree")
    async def docs_tree(lang: str) -> JSONResponse:
        if not is_doc_lang(lang):
            return JSONResponse(json_error("unknown_lang"), status_code=404)
        lang_root = Path(root) / lang
        if not lang_root.exists():
            return JSONResponse(
                {"error": "not_generated", "hint": f"Run: just docs-{docs_recipe_slug(lang)}"},
                status_code=404,
            )
        try:
            tree = _build_docs_tree(str(lang_root), "")
        except OSError as exc:
            return JSONResponse({"error": "tree_failed", "detail": str(exc)}, status_code=500)
        return JSONResponse({"lang": lang, "tree": tree})

    @router.get("/api/v1/docs/{lang}/file")
    async def docs_file(lang: str, request: Request) -> Response:
        if not is_doc_lang(lang):
            return JSONResponse(json_error("unknown_lang"), status_code=404)
        rel = request.query_params.get("path") or "README.md"
        lang_root = str(Path(root) / lang)
        abs_path = _safe_join(lang_root, rel)
        if abs_path is None:
            return JSONResponse(json_error("unsafe_path"), status_code=400)
        if not abs_path.endswith(".md"):
            return JSONResponse(json_error("not_markdown"), status_code=400)
        try:
            content = Path(abs_path).read_text(encoding="utf-8")
        except OSError as exc:
            return JSONResponse({"error": "not_found", "detail": str(exc)}, status_code=404)
        return PlainTextResponse(content, media_type="text/markdown; charset=utf-8")

    return router
