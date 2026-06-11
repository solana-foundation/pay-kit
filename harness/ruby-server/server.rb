# frozen_string_literal: true

# Cross-language harness adapter that proves the PayKit dual-protocol
# claim: one Ruby server, one /paid route, two settle paths (x402:exact
# and mpp:charge). The harness orchestrator picks the protocol per
# scenario by setting either `X402_HARNESS_*` or `MPP_HARNESS_*` env;
# this adapter auto-detects which one is active and wires accordingly.
#
# x402 path: routes through PayKit::Pricing + dispatcher (one gate,
# inline coercion). The x402 wire format is uniform across scenarios.
#
# MPP path: bypasses PayKit's gate DSL and drives PayKit::Protocols::Mpp::Server::Charge
# directly. The harness matrix exercises facets PayKit's Gate doesn't
# model yet (per-split ataCreationRequired + memo, custom settlement
# headers, push-mode credentials, replay-source idempotency) so the
# harness builds the method + server with explicit knobs from env.

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

# When the harness orchestrator sets PAY_KIT_HARNESS_PROTOCOL the
# adapter trusts that hint (the cross-language matrix populates both
# X402_HARNESS_* and MPP_HARNESS_* from the same surfpool fixtures, so
# namespace probing alone is ambiguous). Otherwise the adapter falls
# back to "exactly one namespace must be populated".
explicit_protocol = ENV["PAY_KIT_HARNESS_PROTOCOL"].to_s.strip.downcase
case explicit_protocol
when "x402"
  x402_active = true
  mpp_active = false
when "mpp", "charge"
  x402_active = false
  mpp_active = true
else
  x402_active = !ENV["X402_HARNESS_RPC_URL"].to_s.empty?
  mpp_active  = !ENV["MPP_HARNESS_RPC_URL"].to_s.empty?
  if x402_active == mpp_active
    warn "ruby-server: set exactly one of X402_HARNESS_RPC_URL / MPP_HARNESS_RPC_URL, or set PAY_KIT_HARNESS_PROTOCOL=x402|mpp"
    exit 2
  end
end
protocol = x402_active ? :x402 : :mpp

# --- per-protocol setup -------------------------------------------------

if x402_active
  rpc_url            = require_env("X402_HARNESS_RPC_URL")
  pay_to             = require_env("X402_HARNESS_PAY_TO")
  facilitator_secret = require_env("X402_HARNESS_FACILITATOR_SECRET_KEY")
  amount_raw         = optional_env("X402_HARNESS_PRICE", "$0.001")
  mint_raw           = optional_env("X402_HARNESS_MINT", "USDC")
  network_raw        = optional_env("X402_HARNESS_NETWORK", ::PayCore::Solana::Caip2::DEVNET)
  resource_path      = optional_env("X402_HARNESS_RESOURCE_PATH", "/paid")

  amount_decimal = amount_raw.delete_prefix("$").sub(/\A0+(?=\d)/, "")
  network_sym = case network_raw
  when ::PayCore::Solana::Caip2::MAINNET then :solana_mainnet
  when ::PayCore::Solana::Caip2::DEVNET then :solana_devnet
  else :solana_localnet
  end

  PayKit.configure do |c|
    c.network = network_sym
    c.accept = [:x402]
    c.rpc_url = rpc_url
    c.stablecoins = [mint_raw.to_sym]
    c.operator do |op|
      op.recipient = pay_to
      op.signer = PayKit::Signer.json(facilitator_secret)
    end
  end

  mint_for_gate = mint_raw.to_sym
  amount_for_gate = amount_decimal
  pricing_class = Class.new(PayKit::Pricing) do
    define_method(:build_gates) do
      gate :paid, amount: usd(amount_for_gate, mint_for_gate), description: "PayKit harness"
    end
  end
  PayKit.pricing = pricing_class.new

  dispatcher = PayKit::Rack::Dispatcher.new(config: PayKit.config, pricing: PayKit.pricing)
else
  # --- MPP direct-mode wiring -----------------------------------------

  rpc_url           = require_env("MPP_HARNESS_RPC_URL")
  pay_to            = require_env("MPP_HARNESS_PAY_TO")
  mint_raw          = require_env("MPP_HARNESS_MINT")
  amount_raw        = require_env("MPP_HARNESS_AMOUNT")
  mpp_secret        = optional_env("MPP_HARNESS_SECRET_KEY", "pay-kit-harness-secret")
  network_raw       = optional_env("MPP_HARNESS_NETWORK", "localnet")
  resource_path     = optional_env("MPP_HARNESS_RESOURCE_PATH", "/paid")
  settlement_header = optional_env("MPP_HARNESS_SETTLEMENT_HEADER", "x-payment-settlement-signature")
  decimals_raw      = optional_env("MPP_HARNESS_DECIMALS", "6")
  asset_kind        = optional_env("MPP_HARNESS_ASSET_KIND", "spl")
  splits_raw        = optional_env("MPP_HARNESS_SPLITS", "[]")
  replay_amount     = ENV["MPP_HARNESS_REPLAY_SOURCE_AMOUNT"]
  replay_path       = ENV["MPP_HARNESS_REPLAY_SOURCE_PATH"]

  splits_for_method = JSON.parse(splits_raw)
  splits_for_method = nil if splits_for_method.is_a?(Array) && splits_for_method.empty?

  network_label = case network_raw
  when "mainnet" then "mainnet"
  when "devnet" then "devnet"
  else "localnet"
  end

  # SOL-native vs SPL: PayCore::Solana::Mints.decimals_for needs an
  # SPL mint symbol/address. For SOL we pass currency="SOL" and let
  # the method skip the mint table.
  currency = (asset_kind == "sol") ? "SOL" : mint_raw

  method = ::PayKit::Protocols::Mpp::Protocol::Solana.charge(
    recipient: pay_to,
    currency: currency,
    network: network_label,
    rpc: rpc_url,
    decimals: Integer(decimals_raw, 10)
  )

  mpp_server = ::PayKit::Protocols::Mpp.create(
    method: method,
    secret_key: mpp_secret,
    realm: "PayKit Harness",
    settlement_header: settlement_header
  )

  # Replay-source scenarios bind a second logical resource to the same
  # server so a credential issued for path A can be probed against
  # path B. The MPP server's replay store is per-instance, so reusing
  # `mpp_server` already gives us that contract; we just route both
  # paths through the same handler.
  replay_resource_path = (replay_path && !replay_path.empty?) ? replay_path : nil
  replay_amount_int = replay_amount ? Integer(replay_amount, 10) : nil

  amount_int = Integer(amount_raw, 10)
end

# --- HTTP loop ----------------------------------------------------------

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
  implementation: "ruby",
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

# Per-request handler for the x402 path (PayKit dispatcher).
serve_x402 = proc do |conn, req|
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
end

# Per-request handler for the MPP path (direct PayKit::Protocols::Mpp::Server::Charge).
serve_mpp = proc do |conn, req|
  amount_units = if replay_resource_path && req[:path] == replay_resource_path
    replay_amount_int
  else
    amount_int
  end

  authorization = req[:headers]["authorization"]
  result = mpp_server.charge(
    authorization,
    amount: amount_units.to_s,
    description: "PayKit harness protected content",
    splits: splits_for_method
  )

  case result
  when ::PayKit::Protocols::Mpp::Settlement
    headers = {"content-type" => "application/json"}.merge(result.headers || {})
    write_response(conn, 200, headers, {ok: true, paid: true, protocol: "mpp", transaction: result.signature})
  when ::PayKit::Protocols::Mpp::Challenge
    headers = {"content-type" => "application/json", "www-authenticate" => result.www_authenticate}
    write_response(conn, 402, headers, result.body)
  else
    write_response(conn, 500, {"content-type" => "application/json"}, {error: "unexpected MPP result: #{result.class}"})
  end
end

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

    # Both the primary resource and (for MPP replay scenarios) the
    # replay-source path route to the same handler. The handler picks
    # the per-path expected amount.
    path_matches = (req[:path] == resource_path) ||
      (!x402_active && replay_resource_path && req[:path] == replay_resource_path)

    unless req[:method] == "GET" && path_matches
      write_response(conn, 404, {"content-type" => "application/json"}, {"error" => "not_found"})
      conn.close
      next
    end

    if x402_active
      serve_x402.call(conn, req)
    else
      serve_mpp.call(conn, req)
    end
    conn.close
  rescue ::PayKit::InvalidProof => e
    body = {error: e.code.to_s, message: e.detail}
    body[:code] = e.spec_code if e.respond_to?(:spec_code) && e.spec_code
    write_response(conn, 402, {"content-type" => "application/json"}, body)
    conn.close
  rescue ::PayKit::Protocols::Mpp::Error => e
    code = e.respond_to?(:code) ? e.code : nil
    body = {error: code || "payment_invalid", message: e.message}
    body[:code] = code if code
    write_response(conn, 402, {"content-type" => "application/json"}, body)
    conn.close
  rescue StandardError => e
    warn "ruby-server error: #{e.message}\n#{e.backtrace.first(5).join("\n")}"
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
