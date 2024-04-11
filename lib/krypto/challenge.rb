# frozen_string_literal: true

require "rbnacl"
require "msgpack"
require "openssl"

module Krypto

  MAX_CHALLENGE_SIZE = 4 * 1024 * 1024

  class Challenge
    def self.generate(signing_key, challenge_id, challenge_data, request_data, timestamp: Time.now)
      private_encryption_key = RbNaCl::PrivateKey.generate
      public_encryption_key = private_encryption_key.public_key

      msg = MessagePack.pack(
        InnerChallenge.new(
          publicEncryptionKey: public_encryption_key.to_bytes,
          challengeData: challenge_data,
          requestData: request_data,
          timestamp: timestamp.to_i,
          challengeId: challenge_id
        )
      )

      outer = OuterChallenge.new(
        sig: signing_key.sign(OpenSSL::Digest.new("SHA256"), msg),
        msg: msg
      )

      [outer, private_encryption_key.to_bytes]
    end

    def self.unmarshal(data, png: false, base64: true)
      if data.size > MAX_CHALLENGE_SIZE
        raise "challenge too large"
      end

      data = ::Krypto::Png.decode_blob(data) if png
      data = Base64.strict_decode64(data) if base64
      OuterChallenge.new(MessagePack.unpack(data).slice(*OUTER_CHALLENGE_FIELDS.map(&:to_s)))
    end

    # OuterChallenge is meant as the main challenge entry point. It is a simple wrapper over an internal message.
    OUTER_CHALLENGE_FIELDS = %i[sig msg].freeze
    class OuterChallenge < Struct.new(*OUTER_CHALLENGE_FIELDS, keyword_init: true)
      def to_msgpack(out = "")
        to_h.to_msgpack(out)
      end

      def verify(key)
        return false unless Krypto::Ec.verify(key, sig, msg)

        @inner = InnerChallenge.new(MessagePack.unpack(msg))

        true
      end

      def timestamp
        @inner&.timestamp
      end

      def request_data
        @inner&.requestData
      end

      # respond creates a reponse to the challenge. It accepts 2 keys to sign
      # the response with, the second may be nil.
      def respond(signing_key, signing_key_2, response_data)
        raise "No inner. Unverified?" unless @inner

        public_signing_key_2_der = if !signing_key_2.nil?
          Base64.strict_encode64(signing_key_2.public_to_der)
        else
          ""
        end

        msg = MessagePack.pack(
          Krypto::ChallengeResponse::InnerResponse.new(
            publicSigningKey: Base64.strict_encode64(signing_key.public_to_der),
            publicSigningKey2: public_signing_key_2_der,
            challengeData: @inner.challengeData,
            responseData: response_data,
            timestamp: Time.now.to_i
          )
        )

        sig = Krypto::Ec.sign(signing_key, msg)
        private_encryption_key = RbNaCl::PrivateKey.generate

        sig2 = if !signing_key_2.nil?
          Krypto::Ec.sign(signing_key_2, msg)
        else
          ""
        end

        box = RbNaCl::SimpleBox.from_keypair(@inner.publicEncryptionKey, private_encryption_key)
        sealed = box.encrypt(msg)

        Krypto::ChallengeResponse::OuterResponse.new(
          sig: sig,
          sig2: sig2,
          publicEncryptionKey: private_encryption_key.public_key.to_bytes,
          msg: sealed,
          challengeId: @inner.challengeId
        )
      end
    end

    INNER_CHALLENGE_FIELDS = %i[publicEncryptionKey challengeData requestData timestamp challengeId].freeze
    class InnerChallenge < Struct.new(*INNER_CHALLENGE_FIELDS, keyword_init: true)
      def to_msgpack(out = "")
        to_h.to_msgpack(out)
      end
    end
  end
end
