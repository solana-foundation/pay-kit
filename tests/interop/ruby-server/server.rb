# frozen_string_literal: true

require "json"
require "socket"
require_relative "../../../ruby/lib/solana_mpp"

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

# Build a Solana keypair from the harness byte-array format.
def keypair_from_env(name)
  SolanaMpp::Solana::Keypair.from_json_array(require_env(name))
end

rpc_url = require_env("MPP_INTEROP_RPC_URL")
network = optional_env("MPP_INTEROP_NETWORK", "localnet")
mint = require_env("MPP_INTEROP_MINT")
amount = require_env("MPP_INTEROP_AMOUNT")
pay_to = require_env("MPP_INTEROP_PAY_TO")
secret_key = optional_env("MPP_INTEROP_SECRET_KEY", "mpp-interop-secret-key")
resource_path = optional_env("MPP_INTEROP_RESOURCE_PATH", "/paid")
settlement_header = optional_env("MPP_INTEROP_SETTLEMENT_HEADER", "x-payment-settlement-signature")
replay_path = ENV["MPP_INTEROP_REPLAY_SOURCE_PATH"]
replay_amount = ENV["MPP_INTEROP_REPLAY_SOURCE_AMOUNT"]
splits = JSON.parse(optional_env("MPP_INTEROP_SPLITS", "[]"))
unless splits.is_a?(Array)
  warn "MPP_INTEROP_SPLITS must decode to an array"
  exit 2
end

rpc = SolanaMpp::Solana::RpcClient.new(rpc_url)
fee_payer = keypair_from_env("MPP_INTEROP_FEE_PAYER_SECRET_KEY")
handler = SolanaMpp::Server::ChargeHandler.new(
  challenges: SolanaMpp::Server::ChargeServer.new(
    secret_key: secret_key,
    realm: "MPP Interop"
  ),
  rpc: rpc,
  replay_store: SolanaMpp::MemoryStore.new,
  fee_payer: fee_payer,
  network: network,
  settlement_header: settlement_header
)

# Build one request object for the selected route amount.
def build_charge_request(rpc, amount, mint, pay_to, network, fee_payer_key, splits)
  method_details = {
    "network" => network,
    "decimals" => 6,
    "feePayer" => true,
    "feePayerKey" => fee_payer_key,
    "recentBlockhash" => rpc.latest_blockhash
  }
  method_details["splits"] = splits unless splits.empty?
  SolanaMpp::Intent::ChargeRequest.new(
    amount: amount,
    currency: mint,
    recipient: pay_to,
    description: "Ruby interop protected content",
    method_details: method_details
  )
end

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

shutdown = proc do
  listener.close unless listener.closed?
  exit 0
end
Signal.trap("TERM", &shutdown)
Signal.trap("INT", &shutdown)

loop do
  conn = listener.accept
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

    request = build_charge_request(rpc, protected_amount, mint, pay_to, network, handler.fee_payer_pubkey, splits)
    response = handler.handle(req[:headers]["authorization"], request)
    write_response(conn, response.status, response.headers, response.body)
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
