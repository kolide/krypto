# frozen_string_literal: true

require "rbnacl"
require "msgpack"
require "openssl"

module Krypto
  class Challenge
    OUTER_CHALLENGE_FIELDS = %i[sig msg].freeze
    class OuterChallenge < Struct.new(*OUTER_CHALLENGE_FIELDS, keyword_init: true)
      def to_msgpack(out = "")
        to_h.to_msgpack(out)
      end
    end

    INNER_CHALLENGE_FIELDS = %i[publicEncryptionKey challengeData timeStamp].freeze
    class InnerChallenge < Struct.new(*INNER_CHALLENGE_FIELDS, keyword_init: true)
      def to_msgpack(out = "")
        to_h.to_msgpack(out)
      end
    end

    def self.generate(signing_key, challenge_data)
      private_encryption_key = RbNaCl::PrivateKey.generate
      public_encryption_key = private_encryption_key.public_key

      msg = MessagePack.pack(
        InnerChallenge.new(
          publicEncryptionKey: public_encryption_key.to_bytes,
          challengeData: challenge_data,
          timeStamp: Time.now.to_i
        )
      )

      outer = OuterChallenge.new(
        sig: signing_key.sign(OpenSSL::Digest.new("SHA256"), msg),
        msg: msg
      )

      [outer, private_encryption_key.to_bytes]
    end

    OUTER_RESPONSE_FIELDS = %i[publicEncryptionKey sig msg].freeze
    class OuterResponse < Struct.new(*OUTER_RESPONSE_FIELDS, keyword_init: true)
      def to_msgpack(out = "")
        to_h.to_msgpack(out)
      end
    end

    INNER_RESPONSE_FIELDS = %i[publicSigningKey challengeData responseData timeStamp].freeze
    class InnerResponse < Struct.new(*INNER_RESPONSE_FIELDS, keyword_init: true)
      def to_msgpack(out = "")
        to_h.to_msgpack(out)
      end
    end

    def self.respond(signing_key, counter_party, outer_challenge, response_data)
      if !verify(counter_party, outer_challenge.msg, outer_challenge.sig)
        raise "invalid signature"
      end

      challenge_msg = InnerChallenge.new(MessagePack.unpack(outer_challenge.msg))

      msg = MessagePack.pack(
        InnerResponse.new(
          publicSigningKey: signing_key.public_to_pem,
          challengeData: challenge_msg.challengeData,
          responseData: response_data,
          timeStamp: Time.now.to_i
        )
      )

      sig = signing_key.sign(OpenSSL::Digest.new("SHA256"), msg)
      private_encryption_key = RbNaCl::PrivateKey.generate

      box = RbNaCl::SimpleBox.from_keypair(challenge_msg.publicEncryptionKey, private_encryption_key)
      sealed = box.encrypt(msg)

      OuterResponse.new(
        sig: sig,
        publicEncryptionKey: private_encryption_key.public_key.to_bytes,
        msg: sealed
      )
    end

    def self.open_response_png(private_encryption_key, outer_response)
      data = unpng(outer_response)
      outer = OuterResponse.new(MessagePack.unpack(data))
      open_response(private_encryption_key, outer)
    end

    def self.open_response(private_encryption_key, outer_response)
      public_encryption_key = RbNaCl::PublicKey.new(outer_response.publicEncryptionKey)
      box = RbNaCl::SimpleBox.from_keypair(public_encryption_key, private_encryption_key)
      opened = box.open(outer_response.msg)
      msg = InnerResponse.new(MessagePack.unpack(opened))

      public_signing_key = OpenSSL::PKey::EC.new(msg.publicSigningKey)
      if verify(public_signing_key, opened, outer_response.sig)
        return msg
      end

      raise "invalid signature"
    end

    def self.verify(key, data, sig)
      if key.dsa_verify_asn1(signing_hash(data), sig)
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
