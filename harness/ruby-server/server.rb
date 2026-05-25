# frozen_string_literal: true

require "json"
require "socket"
require_relative "../../ruby/lib/mpp"

# Read a required environment variable for the interop adapter.
def require_env(name)
  value = ENV[name]
  if value.nil? || value.empty?
    warn "Missing required env: #{name}"
    exit 2
  end
  value
end

# Read an optional environment variable.
def optional_env(name, default)
  value = ENV[name]
  value.nil? || value.empty? ? default : value
end

# Build a Solana account from the harness byte-array format.
def account_from_env(name)
  Mpp::Methods::Solana::Account.from_json_array(require_env(name))
end

rpc_url           = require_env("MPP_INTEROP_RPC_URL")
network           = optional_env("MPP_INTEROP_NETWORK", "localnet")
mint              = require_env("MPP_INTEROP_MINT")
amount            = require_env("MPP_INTEROP_AMOUNT")
pay_to            = require_env("MPP_INTEROP_PAY_TO")
secret_key        = optional_env("MPP_INTEROP_SECRET_KEY", "mpp-interop-secret-key")
resource_path     = optional_env("MPP_INTEROP_RESOURCE_PATH", "/paid")
settlement_header = optional_env("MPP_INTEROP_SETTLEMENT_HEADER", "x-payment-settlement-signature")
replay_path       = ENV["MPP_INTEROP_REPLAY_SOURCE_PATH"]
replay_amount     = ENV["MPP_INTEROP_REPLAY_SOURCE_AMOUNT"]
# B34 / push-mode: when the harness drives this server in push mode the
# challenge MUST NOT advertise a server-side fee payer (the Ruby verifier
# rejects type=signature credentials whenever methodDetails.feePayer == true,
# see methods/solana/verifier.rb). Passing fee_payer: nil omits both
# feePayer and feePayerKey from the challenge so the push path verifies.
payment_mode      = optional_env("MPP_INTEROP_PAYMENT_MODE", "pull")
splits            = JSON.parse(optional_env("MPP_INTEROP_SPLITS", "[]"))
unless splits.is_a?(Array)
  warn "MPP_INTEROP_SPLITS must decode to an array"
  exit 2
end

server = Mpp.create(
  method: Mpp::Methods::Solana.charge(
    recipient: pay_to,
    currency:  mint,
    network:   network,
    rpc:       rpc_url,
    fee_payer: payment_mode == "push" ? nil : account_from_env("MPP_INTEROP_FEE_PAYER_SECRET_KEY")
  ),
  secret_key:        secret_key,
  realm:             "MPP Interop",
  settlement_header: settlement_header
)

# Read one HTTP request from a socket.
def read_request(conn)
  request_line = conn.gets
  return nil if request_line.nil? || request_line.strip.empty?

  method, raw_path = request_line.strip.split(/\s+/, 3)
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

# Write one HTTP response to a socket.
def write_response(conn, status, headers, body)
  reason = {
    200 => "OK",
    402 => "Payment Required",
    404 => "Not Found",
    500 => "Server Error"
  }.fetch(status, "Server Error")
  payload = body.is_a?(String) ? body : JSON.generate(body)
  merged = {"connection" => "close", "content-length" => payload.bytesize.to_s}.merge(headers)
  conn.write("HTTP/1.1 #{status} #{reason}\r\n")
  merged.each { |name, value| conn.write("#{name}: #{value}\r\n") }
  conn.write("\r\n")
  conn.write(payload)
end

listener = TCPServer.new("127.0.0.1", 0)
port = listener.addr[1]
$stdout.write(JSON.generate({
  type: "ready",
  implementation: "ruby",
  role: "server",
  port: port,
  capabilities: ["charge"]
}) + "\n")
$stdout.flush

# Graceful shutdown: signal traps cannot safely take the same Mutex the
# accept loop is parked on (Ruby raises `recursive locking (ThreadError)`
# or `deadlock; recursive locking` when SIGTERM lands while `TCPServer#accept`
# is blocked). Instead, flip an atomic flag from the trap context and close
# the listener from a separate thread so `accept` returns with `IOError`
# which the main loop treats as a clean exit. No `exit` from inside trap.
shutting_down = false
shutdown = proc do
  next if shutting_down
  shutting_down = true
  Thread.new do
    begin
      listener.close unless listener.closed?
    rescue StandardError
      # Listener already torn down; nothing to do.
    end
  end
end
Signal.trap("TERM", &shutdown)
Signal.trap("INT", &shutdown)

loop do
  begin
    conn = listener.accept
  rescue IOError, Errno::EBADF
    # Listener was closed by the shutdown trap; exit the accept loop cleanly.
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

    protected_amount = if req[:method] == "GET" && req[:path] == resource_path
      amount
    elsif req[:method] == "GET" && replay_path && req[:path] == replay_path
      replay_amount || amount
    end

    if protected_amount.nil?
      write_response(conn, 404, {"content-type" => "application/json"}, {"error" => "not_found"})
      conn.close
      next
    end

    result = server.charge(
      req[:headers]["authorization"],
      amount:      protected_amount,
      description: "Ruby interop protected content",
      splits:      splits.empty? ? nil : splits
    )

    case result
    when Mpp::Challenge
      write_response(conn, result.status, result.headers.merge("content-type" => "application/json"), result.body)
    when Mpp::Settlement
      write_response(conn, result.status, result.headers.merge("content-type" => "application/json"), {"ok" => true, "paid" => true})
    end
    conn.close
  rescue StandardError => e
    warn "interop ruby server error: #{e.message}"
    begin
      write_response(conn, 500, {"content-type" => "application/json"}, {"error" => e.message})
    rescue StandardError
      nil
    ensure
      conn.close unless conn.closed?
    end
  end
end

exit 0
