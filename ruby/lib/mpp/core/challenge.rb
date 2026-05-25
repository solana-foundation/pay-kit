# frozen_string_literal: true

require "date"
require "openssl"
require "time"

module Mpp
  module Core
    # Payment challenge from a `WWW-Authenticate` header.
    class Challenge
      attr_reader :id, :realm, :method, :intent, :request, :expires, :description, :digest, :opaque

      def initialize(id:, realm:, method:, intent:, request:, expires: nil, description: nil, digest: nil, opaque: nil)
        raise ArgumentError, "challenge id is required" if id.to_s.empty?
        raise ArgumentError, "realm is required" if realm.to_s.empty?
        raise ArgumentError, "method must be lowercase ASCII" unless method.to_s.match?(/\A[a-z]+\z/)
        raise ArgumentError, "intent is required" if intent.to_s.empty?
        raise ArgumentError, "request is required" if request.to_s.empty?

        @id = id.to_s
        @realm = realm.to_s
        @method = method.to_s
        @intent = intent.to_s.downcase
        @request = request.to_s
        @expires = present(expires)
        @description = present(description)
        @digest = present(digest)
        @opaque = present(opaque)
      end

      # Create a stateless HMAC-bound challenge.
      def self.with_secret(secret_key:, realm:, method:, intent:, request:, expires: nil, description: nil, digest: nil, opaque: nil)
        request_json = Json.canonical_generate(request)
        encoded_request = Base64Url.encode(request_json)
        new(
          id: compute_id(
            secret_key: secret_key,
            realm: realm,
            method: method,
            intent: intent,
            request: encoded_request,
            expires: expires,
            digest: digest,
            opaque: opaque
          ),
          realm: realm,
          method: method,
          intent: intent,
          request: encoded_request,
          expires: expires,
          description: description,
          digest: digest,
          opaque: opaque
        )
      end

      # Compute the HMAC challenge ID used by the Rust reference.
      def self.compute_id(secret_key:, realm:, method:, intent:, request:, expires: nil, digest: nil, opaque: nil)
        input = [realm, method, intent, request, expires.to_s, digest.to_s, opaque.to_s].join("|")
        Base64Url.encode(OpenSSL::HMAC.digest("sha256", secret_key, input))
      end

      # Verify this challenge was issued with `secret_key`.
      def verify?(secret_key)
        expected = self.class.compute_id(
          secret_key: secret_key,
          realm: realm,
          method: method,
          intent: intent,
          request: request,
          expires: expires,
          digest: digest,
          opaque: opaque
        )
        secure_compare(expected, id)
      end

      # Return true if the challenge is expired or has an invalid timestamp
      # (fail-closed). RFC 3339 parsing is delegated to {Rfc3339Parser}.
      def expired?(now: Time.now.utc)
        return false if expires.nil?

        parsed = Rfc3339Parser.parse(expires)
        return true if parsed.nil?

        parsed <= now
      end

      # Decode the base64url canonical JSON request.
      def decode_request
        Json.parse(Base64Url.decode(request))
      end

      # Convert to the credential challenge echo shape.
      def to_echo
        ChallengeEcho.new(
          id: id,
          realm: realm,
          method: method,
          intent: intent,
          request: request,
          expires: expires,
          digest: digest,
          opaque: opaque
        )
      end

      private

      def present(value)
        (value.nil? || value.to_s.empty?) ? nil : value.to_s
      end

      def secure_compare(left, right)
        return false unless left.bytesize == right.bytesize

        left.bytes.zip(right.bytes).reduce(0) { |memo, pair| memo | (pair[0] ^ pair[1]) }.zero?
      end
    end

    # Challenge fields echoed inside a Payment credential.
    class ChallengeEcho
      attr_reader :id, :realm, :method, :intent, :request, :expires, :digest, :opaque

      def initialize(id:, realm:, method:, intent:, request:, expires: nil, digest: nil, opaque: nil)
        @id = id.to_s
        @realm = realm.to_s
        @method = method.to_s
        @intent = intent.to_s
        @request = request.to_s
        @expires = (expires.nil? || expires.to_s.empty?) ? nil : expires.to_s
        @digest = (digest.nil? || digest.to_s.empty?) ? nil : digest.to_s
        @opaque = (opaque.nil? || opaque.to_s.empty?) ? nil : opaque.to_s
      end

      # Serialize to the wire credential shape.
      def to_h
        compact({
          "id" => id,
          "realm" => realm,
          "method" => method,
          "intent" => intent,
          "request" => request,
          "expires" => expires,
          "digest" => digest,
          "opaque" => opaque
        })
      end

      # Build a challenge echo from decoded JSON.
      def self.from_h(value)
        raise ArgumentError, "challenge must be an object" unless value.is_a?(Hash)

        new(
          id: value.fetch("id"),
          realm: value.fetch("realm"),
          method: value.fetch("method"),
          intent: value.fetch("intent"),
          request: value.fetch("request"),
          expires: value["expires"],
          digest: value["digest"],
          opaque: value["opaque"]
        )
      end

      private

      def compact(value)
        value.reject { |_key, item| item.nil? }
      end
    end
  end
end
