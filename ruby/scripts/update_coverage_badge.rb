# frozen_string_literal: true

require "json"

unless ARGV.length == 2
  warn "usage: ruby scripts/update_coverage_badge.rb <simplecov-resultset.json> <readme.md>"
  exit 2
end

resultset_path, readme_path = ARGV
resultset = JSON.parse(File.read(resultset_path))
coverage = resultset.values.fetch(0).fetch("coverage")

line_total = 0
line_covered = 0
branch_total = 0
branch_covered = 0

coverage.each_value do |metrics|
  metrics.fetch("lines", []).each do |hits|
    next if hits.nil?

    line_total += 1
    line_covered += 1 if hits.positive?
  end

  metrics.fetch("branches", {}).each_value do |branches|
    branches.each_value do |hits|
      branch_total += 1
      branch_covered += 1 if hits.positive?
    end
  end
end

def percentage(covered, total)
  raise "coverage result has no measurable items" if total.zero?

  ((covered.to_f / total) * 100).floor
end

def badge_color(percent)
  case percent
  when 90.. then "brightgreen"
  when 80...90 then "green"
  when 70...80 then "yellowgreen"
  when 60...70 then "yellow"
  when 50...60 then "orange"
  else "red"
  end
end

line_percent = percentage(line_covered, line_total)
branch_percent = percentage(branch_covered, branch_total)
readme = File.read(readme_path)
updated = readme
updated = updated.gsub(
  %r{https://img\.shields\.io/badge/coverage-[0-9.]+%25-[a-z]+},
  "https://img.shields.io/badge/coverage-#{line_percent}%25-#{badge_color(line_percent)}"
)
updated = updated.gsub(
  %r{https://img\.shields\.io/badge/branch%20coverage-[0-9.]+%25-[a-z]+},
  "https://img.shields.io/badge/branch%20coverage-#{branch_percent}%25-#{badge_color(branch_percent)}"
)

if updated == readme
  puts "Coverage badges already at #{line_percent}% line / #{branch_percent}% branch."
else
  File.write(readme_path, updated)
  puts "Updated coverage badges: #{line_percent}% line / #{branch_percent}% branch."
end
