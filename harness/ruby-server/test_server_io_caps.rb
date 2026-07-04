# frozen_string_literal: true

# Regression tests for the hand-rolled Ruby harness HTTP server at
# `harness/ruby-server/server.rb` (finding L-3).
#
# The server hand-parses request headers with `conn.gets` in an unbounded
# loop and does not clamp a declared body length. This drives the real
# server over a raw TCP socket and asserts it now caps both:
#
#   * a single header value beyond the per-header cap  -> 431
#   * an absurd header *count*                         -> 431
#   * a declared body beyond the body cap              -> 413
#
# The caps mirror the Python harness server (16 KiB per-header / 64 KiB
# total headers / 1 MiB body), so the two implementations reject the same
# hostile inputs identically. Every legitimate harness payload -- a base64
# Solana transaction is ~1.6 KiB, and the MPP token cap is itself 16 KiB --
# fits comfortably under these limits.
#
# Run from the `ruby/` directory so the spawned server resolves the SDK
# load path via bundler, exactly as the harness orchestrator launches it:
#
#   cd ruby && bundle exec ruby ../harness/ruby-server/test_server_io_caps.rb

require "json"
require "socket"
require "timeout"
require "minitest/autorun"

class RubyHarnessServerIoCapsTest < Minitest::Test
  SERVER = File.expand_path("server.rb", __dir__)

  # One header value past the 16 KiB per-header cap.
  OVERSIZED_HEADER_VALUE = "A" * (32 * 1024)
  # Far more headers than the count cap allows.
  ABSURD_HEADER_COUNT = 5_000
  # Well beyond the 1 MiB body cap.
  OVERSIZED_BODY_LEN = 4 * 1024 * 1024

  def setup
    key = JSON.generate(Array.new(64) { rand(256) })
    env = {
      "PAY_KIT_HARNESS_PROTOCOL" => "x402",
      "X402_HARNESS_RPC_URL" => "http://127.0.0.1:8899",
      "X402_HARNESS_PAY_TO" => "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
      "X402_HARNESS_FACILITATOR_SECRET_KEY" => key,
      "X402_HARNESS_RESOURCE_PATH" => "/paid",
    }
    reader, writer = IO.pipe
    # Spawn via bundler from the ruby/ project dir so the SDK load path
    # resolves, matching the harness orchestrator's launch command.
    @pid = spawn(env, "bundle", "exec", "ruby", SERVER, out: writer, chdir: File.expand_path("../../ruby", __dir__))
    writer.close
    ready_line = Timeout.timeout(20) { reader.gets }
    reader.close
    refute_nil ready_line, "ruby server did not emit a ready handshake"
    @port = JSON.parse(ready_line).fetch("port")
    wait_for_port(@port)
  end

  def teardown
    return unless @pid

    Process.kill("TERM", @pid)
  rescue Errno::ESRCH
    # already gone
  ensure
    begin
      Process.wait(@pid) if @pid
    rescue Errno::ECHILD
      nil
    end
  end

  def test_oversized_header_value_rejected_with_431
    status = status_line(
      "GET /paid HTTP/1.1\r\nHost: x\r\nX-Overflow: #{OVERSIZED_HEADER_VALUE}\r\nConnection: close\r\n\r\n"
    )
    assert_includes status, " 431 ", "expected 431 for an oversized header value, got #{status.inspect}"
  end

  def test_absurd_header_count_rejected_with_431
    many = (0...ABSURD_HEADER_COUNT).map { |i| "X-#{i}: y\r\n" }.join
    status = status_line("GET /paid HTTP/1.1\r\nHost: x\r\n#{many}Connection: close\r\n\r\n")
    assert_includes status, " 431 ", "expected 431 for an absurd header count, got #{status.inspect}"
  end

  def test_oversized_body_rejected_with_413
    # Declare a 4 MiB body but transmit only two bytes: a clamping server
    # answers 413 from the declared length without reading the body.
    status = status_line(
      "POST /paid HTTP/1.1\r\nHost: x\r\nContent-Length: #{OVERSIZED_BODY_LEN}\r\nConnection: close\r\n\r\n",
      after: "{}"
    )
    assert_includes status, " 413 ", "expected 413 for an oversized declared body, got #{status.inspect}"
  end

  private

  def wait_for_port(port, timeout: 10)
    deadline = Time.now + timeout
    while Time.now < deadline
      begin
        TCPSocket.new("127.0.0.1", port).close
        return
      rescue SystemCallError
        sleep 0.05
      end
    end
    raise "port #{port} did not open within #{timeout}s"
  end

  def status_line(raw, after: nil, timeout: 4)
    socket = TCPSocket.new("127.0.0.1", @port)
    socket.write(raw)
    socket.write(after) if after
    line = Timeout.timeout(timeout) { socket.gets }
    line.to_s.strip
  ensure
    socket&.close
  end
end
