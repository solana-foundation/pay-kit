# frozen_string_literal: true

# yard_to_md — emit GitHub-flavored markdown API docs from YARD's parser.
#
# YARD doesn't ship a maintained markdown template. Instead of forcing one of
# the abandoned templates into the build, we use the YARD::Registry API
# directly: parse lib/, walk every class/module/method, and emit one .md per
# top-level namespace plus a README index.
#
# Invoked by `just docs-rb`. Output goes to ../docs/api/ruby/.

require "yard"
require "fileutils"

OUT_DIR = File.expand_path("../../docs/api/ruby", __dir__)
LIB_GLOB = File.expand_path("../lib/**/*.rb", __dir__)

YARD::Logger.instance.level = YARD::Logger::WARN
YARD::Registry.load(Dir[LIB_GLOB], true)

FileUtils.mkdir_p(OUT_DIR)

def escape_md(text)
  text.to_s.gsub("|", "\\|").tr("\n", " ").strip
end

def render_method(meth)
  buf = "### `#{(meth.scope == :class) ? "." : "#"}#{meth.name}`\n\n"
  if (sig = meth.signature)
    buf << "```ruby\n#{sig}\n```\n\n"
  end
  buf << "#{meth.docstring}\n\n" unless meth.docstring.empty?
  if meth.tags(:param).any?
    buf << "**Parameters**\n\n"
    meth.tags(:param).each do |p|
      buf << "- `#{p.name}` — #{escape_md(p.text)}\n"
    end
    buf << "\n"
  end
  if (ret = meth.tag(:return))
    buf << "**Returns**: #{escape_md(ret.text)}\n\n"
  end
  buf
end

def render_namespace(ns)
  buf = "# `#{ns.path}`\n\n"
  buf << "#{ns.docstring}\n\n" unless ns.docstring.empty?

  classes = ns.children.select { |c| c.type == :class }
  modules = ns.children.select { |c| c.type == :module }
  meths_inst = ns.meths.select { |m| m.scope == :instance && !m.is_alias? }
  meths_class = ns.meths.select { |m| m.scope == :class && !m.is_alias? }

  if classes.any?
    buf << "## Classes\n\n"
    classes.each { |c| buf << "- [`#{c.name}`](##{c.name.to_s.downcase})\n" }
    buf << "\n"
  end
  if modules.any?
    buf << "## Modules\n\n"
    modules.each { |m| buf << "- `#{m.name}`\n" }
    buf << "\n"
  end
  if meths_class.any?
    buf << "## Class methods\n\n"
    meths_class.sort_by(&:name).each { |m| buf << render_method(m) }
  end
  if meths_inst.any?
    buf << "## Instance methods\n\n"
    meths_inst.sort_by(&:name).each { |m| buf << render_method(m) }
  end

  buf
end

# Collect top-level namespaces under PayKit / pay_kit.
root_namespaces = YARD::Registry.all(:class, :module).select do |obj|
  obj.namespace == YARD::Registry.root || obj.namespace.path == "PayKit"
end

# Index
index = +"# Ruby API reference\n\n"
index << "Generated from YARD's parser of `lib/`. One file per top-level namespace.\n\n"
index << "| Namespace | Type | Summary |\n|-----------|------|---------|\n"

root_namespaces.sort_by(&:path).each do |ns|
  slug = ns.path.tr(":", "_").downcase
  path = File.join(OUT_DIR, "#{slug}.md")
  File.write(path, render_namespace(ns))
  summary = escape_md(ns.docstring.summary.to_s)
  summary = "—" if summary.empty?
  index << "| [`#{ns.path}`](./#{slug}.md) | #{ns.type} | #{summary} |\n"
end

index << "\n_Regenerate with_ `just docs-rb`.\n"
File.write(File.join(OUT_DIR, "README.md"), index)
puts "Wrote #{root_namespaces.size} namespace doc(s) + index to #{OUT_DIR}"
