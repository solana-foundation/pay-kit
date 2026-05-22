# frozen_string_literal: true

require "fileutils"
require "json"

module Mpp
  # Atomic replay-protection store interface.
  class Store
    # Insert `value` only if `key` does not exist.
    def put_if_absent(_key, _value)
      raise NotImplementedError
    end
  end

  # Thread-safe in-memory replay store for tests and local development.
  class MemoryStore < Store
    def initialize
      @mutex = Mutex.new
      @values = {}
    end

    # Insert `value` only if `key` has not been consumed.
    def put_if_absent(key, value)
      @mutex.synchronize do
        return false if @values.key?(key)

        @values[key] = value
        true
      end
    end
  end

  # File-backed replay store for examples and single-process deployments.
  #
  # The in-process mutex protects concurrent threads sharing this object, but it
  # is not a cross-process file lock. Production multi-worker servers should
  # provide a shared atomic store such as Redis, Postgres, or DynamoDB.
  class FileStore < Store
    def initialize(path)
      @path = path
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, "{}") unless File.exist?(path)
      @mutex = Mutex.new
    end

    # Insert `value` only if `key` has not been consumed.
    def put_if_absent(key, value)
      @mutex.synchronize do
        data = JSON.parse(File.read(@path))
        return false if data.key?(key)

        data[key] = value
        File.write(@path, JSON.pretty_generate(data))
        true
      end
    end
  end
end
