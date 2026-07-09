# frozen_string_literal: true

# Canonical mpp-tools protocol-conformance runner for the Ruby SDK.
#
# Speaks the per-language adapter ABI documented in
# `harness/src/protocol/README.md`: read one JSON request on stdin
#
#   { "op": "<operation>", "input": <op-specific> }
#
# and write one JSON response on stdout, then exit
#
#   { "success": true,  "result": <op-specific> }
#   { "success": false, "error": "<msg>", "error_type": "<type>" }
#
# Each op maps to the existing `solana-pay-kit` Ruby protocol functions (no
# conformance-only reimplementation):
#
#   challenge.parse  -> Protocol::Core::Headers.parse_www_authenticate
#   challenge.format -> Protocol::Core::Headers.format_www_authenticate
#   credential.parse -> Protocol::Core::Credential.from_authorization_header
#   credential.format-> Protocol::Core::Credential#to_authorization_header
#   receipt.parse    -> Protocol::Core::Headers.parse_receipt
#   receipt.format   -> Protocol::Core::Headers.format_receipt
#   base64url.encode -> PayCore::Base64Url.encode
#   base64url.decode -> PayCore::Base64Url.decode
#   challenge.id     -> Protocol::Core::Challenge.compute_id (over JCS+base64url request)
#
# The `error_type` vocabulary mirrors the TypeScript reference runner:
# parse_error (.parse), format_error (.format), encoding_error (base64url),
# generation_error (challenge.id).

require "json"

lib = File.expand_path("../lib", __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

# The protocol/core files declare `module PayKit::Protocols::Mpp` and assume
# the parent namespaces already exist; predeclare them so the core codec files
# can be required in isolation without dragging in the full server stack.
module PayKit
  module Protocols
    module Mpp
    end
  end
end

require "pay_core/base64_url"
require "pay_core/json"
require "pay_kit/protocols/mpp/protocol/core/challenge"
require "pay_kit/protocols/mpp/protocol/core/credential"
require "pay_kit/protocols/mpp/protocol/core/receipt"
require "pay_kit/protocols/mpp/protocol/core/headers"

module ConformanceRunner
  Core = PayKit::Protocols::Mpp::Protocol::Core
  Headers = Core::Headers

  module_function

  def ok(result)
    {success: true, result: result}
  end

  def fail(message, error_type)
    # SDK error messages may embed raw bytes from an invalid base64url payload
    # (e.g. a request param that decodes to non-UTF-8). Scrub to valid UTF-8 so
    # the ABI response can be JSON-serialized instead of crashing the runner.
    scrubbed = message.to_s.encode("UTF-8", invalid: :replace, undef: :replace)
    {success: false, error: scrubbed, error_type: error_type}
  end

  def header_of(input)
    input.fetch("header")
  end

  def text_of(input)
    input.fetch("text")
  end

  # challenge.parse golden shape carries `request` as the DECODED JSON object,
  # so expose the parsed Challenge with its request decoded back to an object.
  def challenge_to_object(challenge)
    obj = {
      "id" => challenge.id,
      "realm" => challenge.realm,
      "method" => challenge.method,
      "intent" => challenge.intent,
      "request" => challenge.decode_request
    }
    obj["expires"] = challenge.expires unless challenge.expires.nil?
    obj["description"] = challenge.description unless challenge.description.nil?
    obj["digest"] = challenge.digest unless challenge.digest.nil?
    obj["opaque"] = challenge.opaque unless challenge.opaque.nil?
    obj
  end

  # challenge.format input is the canonical challenge object (request is a
  # decoded JSON object); rebuild a Challenge by re-encoding request to the
  # base64url(JCS) wire form the codec expects, then format the header.
  def challenge_from_object(input)
    encoded_request = ::PayCore::Base64Url.encode(
      ::PayCore::Json.canonical_generate(input.fetch("request"))
    )
    Core::Challenge.new(
      id: input.fetch("id"),
      realm: input.fetch("realm"),
      method: input.fetch("method"),
      intent: input.fetch("intent"),
      request: encoded_request,
      expires: input["expires"],
      description: input["description"],
      digest: input["digest"],
      opaque: input["opaque"]
    )
  end

  # credential.format input is the canonical credential object whose nested
  # `challenge.request` is a DECODED JSON object. Re-encode it to the
  # base64url(JCS) wire string the ChallengeEcho echoes verbatim.
  def credential_from_object(input)
    challenge = input.fetch("challenge").dup
    if challenge["request"].is_a?(Hash) || challenge["request"].is_a?(Array)
      challenge["request"] = ::PayCore::Base64Url.encode(
        ::PayCore::Json.canonical_generate(challenge["request"])
      )
    end
    echo = Core::ChallengeEcho.from_h(challenge)
    Core::Credential.new(
      challenge: echo,
      payload: input.fetch("payload"),
      source: input["source"]
    )
  end

  def credential_to_object(credential)
    credential.to_h
  end

  def receipt_from_object(input)
    Core::Receipt.new(
      status: input.fetch("status"),
      method: input.fetch("method"),
      reference: input.fetch("reference"),
      challenge_id: input["challengeId"],
      external_id: input["externalId"],
      timestamp: input.fetch("timestamp")
    )
  end

  # challenge.id input passes `request` as a decoded object and `opaque` as an
  # already-serialized string. Canonicalize+base64url the request, then run the
  # HMAC over the canonical pipe layout (Challenge.compute_id).
  def challenge_id(input)
    encoded_request = ::PayCore::Base64Url.encode(
      ::PayCore::Json.canonical_generate(input.fetch("request", {}))
    )
    Core::Challenge.compute_id(
      secret_key: input.fetch("secretKey"),
      realm: input.fetch("realm", ""),
      method: input.fetch("method", ""),
      intent: input.fetch("intent", ""),
      request: encoded_request,
      expires: input["expires"],
      digest: input["digest"],
      opaque: input["opaque"]
    )
  end

  def dispatch(op, input)
    case op
    when "challenge.parse"
      ok(challenge_to_object(Headers.parse_www_authenticate(header_of(input))))
    when "challenge.format"
      ok({"header" => Headers.format_www_authenticate(challenge_from_object(input))})
    when "credential.parse"
      ok(credential_to_object(Core::Credential.from_authorization_header(header_of(input))))
    when "credential.format"
      ok({"header" => credential_from_object(input).to_authorization_header})
    when "receipt.parse"
      ok(Headers.parse_receipt(header_of(input)).to_h)
    when "receipt.format"
      ok({"header" => Headers.format_receipt(receipt_from_object(input))})
    when "base64url.encode"
      # base64url.encode result is the encoded text.
      ok({"text" => ::PayCore::Base64Url.encode(text_of(input))})
    when "base64url.decode"
      # base64url.decode yields UTF-8 text; the SDK returns binary bytes.
      decoded = ::PayCore::Base64Url.decode(text_of(input))
      ok({"text" => decoded.force_encoding(Encoding::UTF_8)})
    when "challenge.id"
      ok({"id" => challenge_id(input)})
    else
      fail("Unknown operation: #{op}", "unsupported_operation")
    end
  rescue KeyError, ArgumentError, TypeError, JSON::ParserError => error
    fail(error.message, error_type_for(op))
  end

  def error_type_for(op)
    return "parse_error" if op.end_with?(".parse")
    return "format_error" if op.end_with?(".format")
    return "encoding_error" if op.start_with?("base64url.")
    return "generation_error" if op == "challenge.id"

    "unknown_error"
  end

  def run(raw)
    request = JSON.parse(raw)
    dispatch(request.fetch("op"), request.fetch("input"))
  rescue JSON::ParserError => error
    fail("invalid request JSON: #{error.message}", "unknown_error")
  end
end

if $PROGRAM_NAME == __FILE__
  raw = $stdin.read.to_s.strip
  response = ConformanceRunner.run(raw)
  $stdout.write(JSON.generate(response))
end
