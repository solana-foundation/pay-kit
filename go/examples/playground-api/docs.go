package main

// Serves the generated API reference markdown from <repo-root>/docs/api,
// with a path-escape guard. Override the root with the DOCS_ROOT env var
// when running the binary outside the repository checkout.

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// docLangs are the languages the playground docs browser knows about.
var docLangs = []string{"typescript", "rust", "go", "python", "ruby", "php", "lua", "kotlin", "swift"}

// docsTreeNode is one entry of the docs file tree.
type docsTreeNode struct {
	// Name is the base name of the file or directory (e.g. "README.md").
	Name string `json:"name"`
	// Path is the slash-separated path relative to the language docs root;
	// the web app passes it back as the ?path= query of the file endpoint.
	Path string `json:"path"`
	// Type is "dir" for directories and "file" for markdown files; dirs
	// sort before files within a level.
	Type string `json:"type"`
	// Children holds the directory's child nodes; omitted for files.
	Children []docsTreeNode `json:"children,omitempty"`
}

// docsRoot resolves the generated-docs directory.
func docsRoot(repoRoot string) string {
	if override := os.Getenv("DOCS_ROOT"); override != "" {
		return override
	}
	if repoRoot == "" {
		return ""
	}
	return filepath.Join(repoRoot, "docs", "api")
}

// registerDocs mounts the generated-docs browsing endpoints.
func registerDocs(mux *http.ServeMux, a *app) {
	root := docsRoot(a.repoRoot)

	mux.HandleFunc("GET /api/v1/docs", func(w http.ResponseWriter, _ *http.Request) {
		available := map[string]bool{}
		for _, lang := range docLangs {
			_, err := os.Stat(filepath.Join(root, lang, "README.md"))
			available[lang] = err == nil
		}
		writeJSON(w, http.StatusOK, map[string]any{"root": root, "available": available})
	})

	mux.HandleFunc("GET /api/v1/docs/{lang}/tree", func(w http.ResponseWriter, r *http.Request) {
		lang := r.PathValue("lang")
		if !isDocLang(lang) {
			writeJSONError(w, http.StatusNotFound, "unknown_lang")
			return
		}
		langRoot := filepath.Join(root, lang)
		if _, err := os.Stat(langRoot); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{
				"error": "not_generated",
				"hint":  "Run: just docs-" + docsRecipeSlug(lang),
			})
			return
		}
		tree, err := buildDocsTree(langRoot, "")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":  "tree_failed",
				"detail": err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"lang": lang, "tree": tree})
	})

	mux.HandleFunc("GET /api/v1/docs/{lang}/file", func(w http.ResponseWriter, r *http.Request) {
		lang := r.PathValue("lang")
		if !isDocLang(lang) {
			writeJSONError(w, http.StatusNotFound, "unknown_lang")
			return
		}
		rel := r.URL.Query().Get("path")
		if rel == "" {
			rel = "README.md"
		}
		rel = filepath.FromSlash(rel)
		if !filepath.IsLocal(rel) {
			writeJSONError(w, http.StatusBadRequest, "unsafe_path")
			return
		}
		if !strings.HasSuffix(rel, ".md") {
			writeJSONError(w, http.StatusBadRequest, "not_markdown")
			return
		}
		content, err := readInRoot(filepath.Join(root, lang), rel)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{
				"error":  "not_found",
				"detail": err.Error(),
			})
			return
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = w.Write(content)
	})
}

// isDocLang reports whether lang is a known docs language.
func isDocLang(lang string) bool {
	for _, known := range docLangs {
		if lang == known {
			return true
		}
	}
	return false
}

// buildDocsTree walks the language docs directory: folders first, then
// markdown files, both alphabetical, skipping dotfiles and node_modules.
func buildDocsTree(absDir, relDir string) ([]docsTreeNode, error) {
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return nil, err
	}
	nodes := []docsTreeNode{}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || name == "node_modules" {
			continue
		}
		relPath := name
		if relDir != "" {
			relPath = relDir + "/" + name
		}
		if entry.IsDir() {
			children, err := buildDocsTree(filepath.Join(absDir, name), relPath)
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, docsTreeNode{Name: name, Path: relPath, Type: "dir", Children: children})
		} else if strings.HasSuffix(name, ".md") {
			nodes = append(nodes, docsTreeNode{Name: name, Path: relPath, Type: "file"})
		}
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Type != nodes[j].Type {
			return nodes[i].Type == "dir"
		}
		return nodes[i].Name < nodes[j].Name
	})
	return nodes, nil
}

// readInRoot reads rel from dir, refusing any path (or symlink) that
// escapes dir.
func readInRoot(dir, rel string) ([]byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.ReadFile(rel)
}

// docsRecipeSlug maps a docs language to its justfile recipe suffix.
func docsRecipeSlug(lang string) string {
	switch lang {
	case "typescript":
		return "ts"
	case "rust":
		return "rs"
	case "python":
		return "py"
	case "ruby":
		return "rb"
	case "kotlin":
		return "kt"
	default:
		return lang
	}
}
