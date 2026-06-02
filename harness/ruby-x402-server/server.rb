#!/usr/bin/env ruby
# frozen_string_literal: true

# Thin harness adapter. All library logic lives in
# `ruby/lib/x402/server/exact.rb`; this adapter only reads the
# harness env vars, spins a 127.0.0.1:0 TCP loop, and serializes
# `PayKit::Protocols::X402::Server::Exact.response_for` tuples to HTTP/1.1.
#
# Mirrors the Rust spine adapter at
# `rust/crates/x402/src/bin/interop_server.rs`. Sister adapter for
# the PayKit umbrella surface lives at `harness/ruby-server/server.rb`.

require "json"
require "socket"

$LOAD_PATH.unshift(File.expand_path("../../ruby/lib", __dir__))
require "pay_kit"

server = TCPServer.new("127.0.0.1", 0)
running = true

def interop_config
  # The harness-specific X402_INTEROP_* env vars are parsed via
  # `Config.from_interop_env`; production callers wire
  # `PayKit::Protocols::X402::Server::Exact::Config.new(rpc_url: ..., pay_to: ..., ...)`
  # with typed kwargs directly.
  @interop_config ||= PayKit::Protocols::X402::Server::Exact::Config.from_interop_env
end

def read_headers(connection)
  headers = {}
  loop do
    line = connection.gets
    break if line.nil? || line.strip.empty?

    name, value = line.split(":", 2)
    headers[name] = value.strip if name && value
  end
  headers
end

def write_response(connection, status, headers, body)
  encoded = JSON.generate(body)
  reason = case status
           when 200 then "OK"
           when 402 then "Payment Required"
           when 404 then "Not Found"
           else "Not Implemented"
           end

  connection.write("HTTP/1.1 #{status} #{reason}\r\n")
  connection.write("content-type: application/json\r\n")
  headers.each do |name, value|
    connection.write("#{name}: #{value}\r\n")
  end
  connection.write("content-length: #{encoded.bytesize}\r\n")
  connection.write("connection: close\r\n\r\n")
  connection.write(encoded)
end

shutdown = proc do
  running = false
  begin
    server.close unless server.closed?
  rescue IOError, ThreadError
    nil
  end
end

trap("TERM", &shutdown)
trap("INT", &shutdown)

puts JSON.generate(
  PayKit::Protocols::X402::Server::Exact::CAPABILITY_PAYLOAD.merge(type: "ready", port: server.addr[1])
)
$stdout.flush

while running
  begin
    begin
      connection = server.accept
    rescue IOError, ThreadError
      break
    end

    begin
      request_line = connection.gets.to_s
      path = (request_line.split[1] || "/").split("?", 2).first
      headers = read_headers(connection)

      status, response_headers, body = PayKit::Protocols::X402::Server::Exact.response_for(path, headers, interop_config)
      write_response(connection, status, response_headers, body)
    rescue Errno::EPIPE, IOError => error
      warn "dropped connection: #{error.class}: #{error.message}"
    end
  ensure
    connection&.close unless connection&.closed?
  end
end
