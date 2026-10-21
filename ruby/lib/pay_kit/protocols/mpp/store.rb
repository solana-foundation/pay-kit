# frozen_string_literal: true

require "fileutils"
require "json"

module PayKit::Protocols::Mpp
  # Atomic replay-protection store interface.
  #
  # A store implements `put_if_absent(key, value)` (insert only if `key` does
  # not exist) and `key?(key)` (whether `key` exists; read only, never creates
  # it). `key?` is deliberately not stubbed here: the consumed-signature
  # ledger checks `respond_to?(:key?)` at construction, and an inherited stub
  # would let a store without it boot and then raise NotImplementedError after
  # a payment was broadcast.
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

    def key?(key)
      @mutex.synchronize { @values.key?(key) }
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

    def key?(key)
      @mutex.synchronize { JSON.parse(File.read(@path)).key?(key) }
    end
  end
end
