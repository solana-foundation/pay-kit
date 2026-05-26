# frozen_string_literal: true

# Cross-language harness adapter that proves the PayKit dual-protocol
# claim: one Ruby server, one /paid route, two settle paths (x402:exact
# and mpp:charge). The harness orchestrator picks the protocol per
# scenario by setting either `X402_INTEROP_*` or `MPP_INTEROP_*` env;
# this adapter auto-detects which one is active and configures PayKit
# accordingly.
#
# When ts-x402 client (or rust-x402) targets this server, requests
# carry `PAYMENT-SIGNATURE`. When ts-mpp client targets it, requests
# carry `Authorization: Payment`. PayKit::Rack::Dispatcher chooses the
# right adapter from `gate.accept` plus header detection.

require "json"
require "rack"
require "socket"
require "stringio"

require_relative "../../ruby/lib/solana_pay_kit"

# --- env helpers -------------------------------------------------------

def require_env(name)
  value = ENV[name]
  if value.nil? || value.empty?
    warn "Missing required env: #{name}"
    exit 2
  end
  value
end

def optional_env(name, default)
  value = ENV[name]
  value.nil? || value.empty? ? default : value
end

# --- detect intent -----------------------------------------------------

x402_active = !ENV["X402_INTEROP_RPC_URL"].to_s.empty?
mpp_active  = !ENV["MPP_INTEROP_RPC_URL"].to_s.empty?
if x402_active == mpp_active
  warn "pay-kit-server: set exactly one of X402_INTEROP_RPC_URL or MPP_INTEROP_RPC_URL"
  exit 2
end
protocol = x402_active ? :x402 : :mpp

# --- read env per active protocol --------------------------------------

if x402_active
  rpc_url            = require_env("X402_INTEROP_RPC_URL")
  pay_to             = require_env("X402_INTEROP_PAY_TO")
  facilitator_secret = require_env("X402_INTEROP_FACILITATOR_SECRET_KEY")
  amount_raw         = optional_env("X402_INTEROP_PRICE", "$0.001")
  mint_raw           = optional_env("X402_INTEROP_MINT", "USDC")
  network_raw        = optional_env("X402_INTEROP_NETWORK", ::PayCore::Solana::Caip2::DEVNET)
  resource_path      = optional_env("X402_INTEROP_RESOURCE_PATH", "/paid")
  mpp_secret         = nil
else
  rpc_url            = require_env("MPP_INTEROP_RPC_URL")
  pay_to             = require_env("MPP_INTEROP_PAY_TO")
  mint_raw           = require_env("MPP_INTEROP_MINT")
  amount_raw         = require_env("MPP_INTEROP_AMOUNT")
  mpp_secret         = optional_env("MPP_INTEROP_SECRET_KEY", "pay-kit-interop-secret")
  network_raw        = optional_env("MPP_INTEROP_NETWORK", "localnet")
  resource_path      = optional_env("MPP_INTEROP_RESOURCE_PATH", "/paid")
  facilitator_secret = nil
end

# Normalize the harness amount into a decimal-dollar string. x402
# arrives as "$0.001"; MPP arrives as integer micro-units ("1000" =
# $0.001 assuming 6-decimal USDC). PayKit::Price wants the customer-
# facing decimal so we converge to the same shape.
amount_decimal =
  if x402_active
    amount_raw.delete_prefix("$").sub(/\A0+(?=\d)/, "")
  else
    units = Integer(amount_raw, 10)
    whole, frac = units.divmod(1_000_000)
    if frac.zero?
      whole.to_s
    else
      "#{whole}.#{format("%06d", frac).sub(/0+\z/, "")}"
    end
  end

# Map the harness network string to a PayKit network symbol. The MPP
# harness uses bare names; the x402 harness uses CAIP-2 strings.
network_sym =
  if network_raw.start_with?("solana:")
    case network_raw
    when ::PayCore::Solana::Caip2::MAINNET then :solana_mainnet
    when ::PayCore::Solana::Caip2::DEVNET then :solana_devnet
    else :solana_localnet
    end
  else
    case network_raw
    when "mainnet" then :solana_mainnet
    when "devnet" then :solana_devnet
    else :solana_localnet
    end
  end

# --- configure PayKit ---------------------------------------------------

PayKit.configure do |c|
  c.pay_to = pay_to
  c.network = network_sym
  c.accept = [protocol]
  # Pin the harness mint as the only stablecoin so the Dispatcher's
  # MPP server picks up the literal pubkey through the unknown-coin
  # pass-through in `mint_for`.
  c.stablecoins = [mint_raw.to_sym]
  if x402_active
    c.x402.facilitator = rpc_url
    c.x402.facilitator_secret_key = facilitator_secret
  else
    c.mpp.realm = "PayKit Interop"
    c.mpp.secret = mpp_secret
  end
end

# --- define the gate ----------------------------------------------------

# The amount is captured from a top-level local via a closure on
# class definition so the test does not need a separate env var.
amount_for_gate = amount_decimal
# Pass the harness mint through PayKit's settlement symbol. The
# `mint_for` pass-through in Dispatcher returns the symbol's string
# form when it isn't a known stablecoin name (e.g. when the harness
# supplies a literal devnet/localnet mint pubkey), so the underlying
# X402::Server::Exact / Mpp::Server gets the exact mint the matrix
# expects.
mint_for_gate = mint_raw.to_sym

pricing_class = Class.new(PayKit::Pricing) do
  define_method(:build_gates) do
    gate :paid,
      amount: usd(amount_for_gate, mint_for_gate),
      description: "PayKit interop protected content"
  end
end

PayKit.pricing = pricing_class.new

# --- HTTP loop ----------------------------------------------------------

dispatcher = PayKit::Rack::Dispatcher.new(config: PayKit.config, pricing: PayKit.pricing)

def read_request(conn)
  request_line = conn.gets
  return nil if request_line.nil? || request_line.strip.empty?

  method, raw_path, = request_line.strip.split(/\s+/, 3)
  headers = {}
  while (line = conn.gets)
    line = line.delete_suffix("\r\n")
    break if line.empty?

    name, value = line.split(":", 2)
    next if value.nil?
    headers[name.downcase] = value.strip
  end
  {method: method, path: raw_path, headers: headers}
end

def write_response(conn, status, headers, body)
  reason = {200 => "OK", 402 => "Payment Required", 404 => "Not Found", 500 => "Server Error"}.fetch(status, "Server Error")
  payload = body.is_a?(String) ? body : JSON.generate(body)
  merged = {"connection" => "close", "content-length" => payload.bytesize.to_s}.merge(headers)
  conn.write("HTTP/1.1 #{status} #{reason}\r\n")
  merged.each { |name, value| conn.write("#{name}: #{value}\r\n") }
  conn.write("\r\n")
  conn.write(payload)
end

def rack_env_for(req, port)
  env = {
    "REQUEST_METHOD" => req[:method],
    "PATH_INFO" => req[:path],
    "QUERY_STRING" => "",
    "SERVER_NAME" => "127.0.0.1",
    "SERVER_PORT" => port.to_s,
    "rack.input" => StringIO.new(""),
    "rack.errors" => $stderr,
    "rack.url_scheme" => "http",
    "rack.version" => [1, 6],
    "rack.multithread" => false,
    "rack.multiprocess" => false,
    "rack.run_once" => false
  }
  req[:headers].each do |name, value|
    env["HTTP_" + name.upcase.tr("-", "_")] = value
  end
  env
end

listener = TCPServer.new("127.0.0.1", 0)
port = listener.addr[1]
$stdout.write(JSON.generate({
  type: "ready",
  implementation: "ruby-pay-kit-server",
  role: "server",
  port: port,
  capabilities: [x402_active ? "exact" : "charge"]
}) + "\n")
$stdout.flush

shutting_down = false
shutdown = proc do
  next if shutting_down
  shutting_down = true
  Thread.new do
    listener.close unless listener.closed?
  rescue StandardError
    nil
  end
end
Signal.trap("TERM", &shutdown)
Signal.trap("INT", &shutdown)

loop do
  begin
    conn = listener.accept
  rescue IOError, Errno::EBADF
    break
  end
  break if shutting_down && conn.nil?

  begin
    req = read_request(conn)
    if req.nil?
      conn.close
      next
    end

    if req[:method] == "GET" && req[:path] == "/health"
      write_response(conn, 200, {"content-type" => "application/json"}, {"ok" => true})
      conn.close
      next
    end

    unless req[:method] == "GET" && req[:path] == resource_path
      write_response(conn, 404, {"content-type" => "application/json"}, {"error" => "not_found"})
      conn.close
      next
    end

    rack_request = ::Rack::Request.new(rack_env_for(req, port))
    gate = PayKit.pricing[:paid]
    proof = dispatcher.verify(gate, rack_request)

    if proof
      headers = {"content-type" => "application/json"}.merge(proof.settlement_headers)
      write_response(conn, 200, headers, {ok: true, paid: true, protocol: proof.protocol.to_s, transaction: proof.transaction})
    else
      challenge = dispatcher.challenge_for(gate, rack_request)
      headers = {"content-type" => "application/json"}.merge(challenge.headers)
      write_response(conn, 402, headers, challenge.to_h)
    end
    conn.close
  rescue ::PayKit::InvalidProof => e
    write_response(conn, 402, {"content-type" => "application/json"}, {error: e.code.to_s, message: e.detail})
    conn.close
  rescue StandardError => e
    warn "pay-kit-server error: #{e.message}\n#{e.backtrace.first(5).join("\n")}"
    begin
      write_response(conn, 500, {"content-type" => "application/json"}, {error: e.message})
    rescue StandardError
      nil
    ensure
      conn.close unless conn.closed?
    end
  end
end

exit 0
