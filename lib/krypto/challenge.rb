# frozen_string_literal: true

require "rbnacl"
require "msgpack"
require "openssl"

module Krypto
  class Challenge
    def self.generate(signing_key, challenge_id, challenge_data, request_data)
      private_encryption_key = RbNaCl::PrivateKey.generate
      public_encryption_key = private_encryption_key.public_key

      msg = MessagePack.pack(
        InnerChallenge.new(
          publicEncryptionKey: public_encryption_key.to_bytes,
          challengeData: challenge_data,
          requestData: request_data,
          timestamp: Time.now.to_i,
          challengeId: challenge_id
        )
      )

      outer = OuterChallenge.new(
        sig: signing_key.sign(OpenSSL::Digest.new("SHA256"), msg),
        msg: msg
      )

      [outer, private_encryption_key.to_bytes]
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

      def respond(signing_key, response_data)
        raise "No inner. Unverified?" unless @inner

        msg = MessagePack.pack(
          Krypto::ChallengeResponse::InnerResponse.new(
            publicSigningKey: signing_key.public_to_pem,
            challengeData: @inner.challengeData,
            responseData: response_data,
            timestamp: Time.now.to_i
          )
        )

        sig = Krypto::Ec.sign(signing_key, msg)
        private_encryption_key = RbNaCl::PrivateKey.generate

        box = RbNaCl::SimpleBox.from_keypair(@inner.publicEncryptionKey, private_encryption_key)
        sealed = box.encrypt(msg)

        Krypto::ChallengeResponse::OuterResponse.new(
          sig: sig,
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
