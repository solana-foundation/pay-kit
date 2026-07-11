# frozen_string_literal: true

require "fileutils"
require "json"
require "tempfile"

# Test-only durable store shared by independently spawned harness workers.
class HarnessReplayStore < ::PayKit::Protocols::Mpp::Store
  def initialize(path)
    super()
    @path = path
    @lock_path = "#{path}.lock"
    FileUtils.mkdir_p(File.dirname(path))
  end

  def durable?
    true
  end

  def shared?
    true
  end

  def put_if_absent(key, value)
    File.open(@lock_path, File::RDWR | File::CREAT, 0o600) do |lock|
      lock.flock(File::LOCK_EX)
      values = load_values
      return false if values.key?(key)

      values[key] = value
      replace_atomically(values)
      true
    end
  end

  private

  def load_values
    return {} unless File.exist?(@path)

    contents = File.read(@path)
    contents.empty? ? {} : JSON.parse(contents)
  end

  def replace_atomically(values)
    directory = File.dirname(@path)
    Tempfile.create([File.basename(@path), ".tmp"], directory, mode: 0o600) do |temp|
      temp.write(JSON.generate(values))
      temp.flush
      temp.fsync
      File.rename(temp.path, @path)
    end
    File.open(directory, File::RDONLY, &:fsync)
  end
end
