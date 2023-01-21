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

    def self.generate(signing_key, challenge_data)
      private_encryption_key = RbNaCl::PrivateKey.generate
      public_encryption_key = private_encryption_key.public_key

      inner = MessagePack.pack(
        InnerChallenge.new(
          publicEncryptionKey: public_encryption_key.to_bytes,
          challengeData: challenge_data
        )
      )

      outer = OuterChallenge.new(
        signature: signing_key.sign(OpenSSL::Digest.new("SHA256"), inner),
        inner: inner
      )

      [outer, private_encryption_key.to_bytes]
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

    def self.respond(signing_key, counter_party, outer_challenge, response_data)
      if !verify(counter_party, outer_challenge.inner, outer_challenge.signature)
        raise "invalid signature"
      end

      challenge_inner = InnerChallenge.new(MessagePack.unpack(outer_challenge.inner))

      inner = MessagePack.pack(
        InnerResponse.new(
          publicSigningKey: signing_key.public_to_pem,
          challengeData: challenge_inner.challengeData,
          responseData: response_data
        )
      )

      signature = signing_key.sign(OpenSSL::Digest.new("SHA256"), inner)
      private_encryption_key = RbNaCl::PrivateKey.generate

      box = RbNaCl::SimpleBox.from_keypair(challenge_inner.publicEncryptionKey, private_encryption_key)
      sealed = box.encrypt(inner)

      OuterResponse.new(
        signature: signature,
        publicEncryptionKey: private_encryption_key.public_key.to_bytes,
        inner: sealed
      )
    end

    def self.open_response_png(private_encryption_key, outer_response)
      data = self.unpng(outer_response)
      outer = OuterResponse.new(MessagePack.unpack(data))
      self.open_response(private_encryption_key, outer)
    end

    def self.open_response(private_encryption_key, outer_response)
      public_encryption_key = RbNaCl::PublicKey.new(outer_response.publicEncryptionKey)
      box = RbNaCl::SimpleBox.from_keypair(public_encryption_key, private_encryption_key)
      opened = box.open(outer_response.inner)
      inner = InnerResponse.new(MessagePack.unpack(opened))

      public_signing_key = OpenSSL::PKey::EC.new(inner.publicSigningKey)
      if verify(public_signing_key, opened, outer_response.signature)
        return inner
      end

      raise "invalid signature"
    end

    def self.verify(key, data, signature)
      if key.dsa_verify_asn1(self.signing_hash(data), signature)
        return true
      end

      false
    end

    def self.signing_hash(data)
      OpenSSL::Digest.new("SHA256").digest(data)
    end

    def self.unpng(data)
      ::Krypto::Png.decode_blob(data)
    end
  end
end
