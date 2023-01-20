# frozen_string_literal: true

require "rbnacl"
require "msgpack"
require "openssl"

module Krypto
  class Challenge
    OUTER_CHALLENGE_FIELDS = %i[signature inner].freeze
    class OuterChallenge < Struct.new(*OUTER_CHALLENGE_FIELDS, keyword_init: true)
      def to_msgpack(out = "")
        to_h.to_msgpack(out)
      end
    end

    INNER_CHALLENGE_FIELDS = %i[publicEncryptionKey challengeData].freeze
    class InnerChallenge < Struct.new(*INNER_CHALLENGE_FIELDS, keyword_init: true)
      def to_msgpack(out = "")
        to_h.to_msgpack(out)
      end
    end

    def generate(signingKey, challengeData)
      privateEncryptionKey = RbNaCl::PrivateKey.generate
      publicEncryptionKey = privateEncryptionKey.public_key

      inner = MessagePack.pack(
        InnerChallenge.new(
          publicEncryptionKey: publicEncryptionKey.to_bytes,
          challengeData: challengeData
        )
      )

      outer = OuterChallenge.new(
        signature: signingKey.sign(OpenSSL::Digest.new("SHA256"), inner),
        inner: inner
      )

      [outer, privateEncryptionKey.to_bytes]
    end

    OUTER_RESPONSE_FIELDS = %i[publicEncryptionKey signature inner].freeze
    class OuterResponse < Struct.new(*OUTER_RESPONSE_FIELDS, keyword_init: true)
      def to_msgpack(out = "")
        to_h.to_msgpack(out)
      end
    end

    INNER_RESPONSE_FIELDS = %i[publicSigningKey challengeData responseData].freeze
    class InnerResponse < Struct.new(*INNER_RESPONSE_FIELDS, keyword_init: true)
      def to_msgpack(out = "")
        to_h.to_msgpack(out)
      end
    end

    def respond(signingKey, counterParty, outerChallenge, responseData)
      if !verify(counterParty, outerChallenge.inner, outerChallenge.signature)
        raise "invalid signature"
      end

      challengeInner = InnerChallenge.new(MessagePack.unpack(outerChallenge.inner))

      inner = MessagePack.pack(
        InnerResponse.new(
          publicSigningKey: signingKey.public_to_pem,
          challengeData: challengeInner.challengeData,
          responseData: responseData
        )
      )

      signature = signingKey.sign(OpenSSL::Digest.new("SHA256"), inner)
      privateEncryptionKey = RbNaCl::PrivateKey.generate

      box = RbNaCl::SimpleBox.from_keypair(challengeInner.publicEncryptionKey, privateEncryptionKey)
      sealed = box.encrypt(inner)

      OuterResponse.new(
        signature: signature,
        publicEncryptionKey: privateEncryptionKey.public_key.to_bytes,
        inner: sealed
      )
    end

    def open_response(privateEncryptionKey, outerResponse)
      publicEncryptionKey = RbNaCl::PublicKey.new(outerResponse.publicEncryptionKey)
      box = RbNaCl::SimpleBox.from_keypair(publicEncryptionKey, privateEncryptionKey)
      opened = box.open(outerResponse.inner)
      inner = InnerResponse.new(MessagePack.unpack(opened))

      publicSigningKey = OpenSSL::PKey::EC.new(inner.publicSigningKey)
      if verify(publicSigningKey, opened, outerResponse.signature)
        return inner
      end

      raise "invalid signature"
    end

    def verify(key, data, signature)
      if key.dsa_verify_asn1(signing_hash(data), signature)
        return true
      end

      false
    end

    def signing_hash(data)
      OpenSSL::Digest.new("SHA256").digest(data)
    end
  end
end
