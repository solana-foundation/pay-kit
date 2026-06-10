-- lua-doc-to-md — extract `---` doc-comments and function signatures from
-- lua source and emit a per-module markdown tree.
--
-- LDoc renders HTML; there is no maintained Markdown template. This script
-- walks the public source roots, captures contiguous `---` comment blocks
-- immediately preceding `local function`, `function M.`, `function NAME.`,
-- and `return { ... }` re-export tables, and emits markdown with the
-- captured signatures + comments.
--
-- Usage:
--   lua scripts/lua-doc-to-md.lua <out-dir> <source-root> [<more-roots> ...]
--
-- Invoked from `just docs-lua`.

local OUT_DIR = arg[1]
local ROOTS = {}
for i = 2, #arg do
  table.insert(ROOTS, arg[i])
end

if not OUT_DIR or #ROOTS == 0 then
  io.stderr:write("usage: lua-doc-to-md.lua <out-dir> <root> [<root> ...]\n")
  os.exit(2)
end

local function mkdirp(path)
  os.execute(("mkdir -p %q"):format(path))
end

local function read_file(path)
  local f, err = io.open(path, "r")
  if not f then return nil, err end
  local content = f:read("*a")
  f:close()
  return content
end

-- Walk the filesystem with `find` so we get a portable recursive listing
-- without LuaFileSystem.
local function list_lua_files(root)
  local files = {}
  local handle = io.popen(("find %q -type f -name '*.lua' 2>/dev/null | sort"):format(root))
  if not handle then return files end
  for line in handle:lines() do
    table.insert(files, line)
  end
  handle:close()
  return files
end

-- Extract (comment, signature) pairs from a single file. The parser is line-based:
-- accumulate `---` lines into a buffer, flush on a function-y line, reset
-- on a blank line outside of a comment block.
local function extract(source)
  local items = {}
  local buf = {}
  for line in source:gmatch("([^\n]*)\n?") do
    if line:match("^%-%-%-") or line:match("^%-%-%-+") then
      table.insert(buf, (line:gsub("^%-%-+%s?", "")))
    elseif line:match("^%-%-") and #buf > 0 then
      -- continuation `-- ...` line right after `---` block
      table.insert(buf, (line:gsub("^%-%-%s?", "")))
    elseif line:match("^%s*function%s") or
           line:match("^%s*local%s+function%s") or
           line:match("^%s*[%w_%.]+%s*=%s*function") then
      if #buf > 0 then
        table.insert(items, {
          comment = table.concat(buf, "\n"),
          signature = line:gsub("^%s+", ""):gsub("%s+$", ""),
        })
        buf = {}
      end
    elseif line:match("^%s*$") then
      buf = {}
    end
  end
  return items
end

local function module_name_for(path)
  -- Strip ".lua" + replace separators with dots, keep the first path
  -- component (the package name).
  local rel = path:gsub("^%./", "")
  rel = rel:gsub("%.lua$", "")
  rel = rel:gsub("/", ".")
  return rel
end

local function escape_md(s)
  return (s:gsub("|", "\\|"))
end

mkdirp(OUT_DIR)

local index_lines = {
  "# Lua API reference",
  "",
  "Extracted from `---` doc comments preceding each function. One file per module.",
  "",
  "| Module | Items |",
  "|--------|------:|",
}

local total = 0
for _, root in ipairs(ROOTS) do
  for _, file in ipairs(list_lua_files(root)) do
    local source = read_file(file)
    if source then
      local items = extract(source)
      if #items > 0 then
        local mod = module_name_for(file)
        local slug = mod:gsub("%.", "_")
        local out = { ("# `%s`"):format(mod), "" }
        for _, item in ipairs(items) do
          out[#out + 1] = ("### `%s`"):format(escape_md(item.signature))
          out[#out + 1] = ""
          out[#out + 1] = item.comment
          out[#out + 1] = ""
        end
        local fh = io.open(OUT_DIR .. "/" .. slug .. ".md", "w")
        fh:write(table.concat(out, "\n"))
        fh:close()
        index_lines[#index_lines + 1] = ("| [`%s`](./%s.md) | %d |"):format(mod, slug, #items)
        total = total + 1
      end
    end
  end
end

index_lines[#index_lines + 1] = ""
index_lines[#index_lines + 1] = "_Regenerate with_ `just docs-lua`."

local fh = io.open(OUT_DIR .. "/README.md", "w")
fh:write(table.concat(index_lines, "\n"))
fh:close()

print(("Wrote %d module doc(s) + index to %s"):format(total, OUT_DIR))
