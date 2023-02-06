# frozen_string_literal: true

require "rbnacl"
require "msgpack"
require "openssl"

module Krypto
  class ChallengeResponse
    def self.unmarshal(data, png: false, base64: true)
      data = ::Krypto::Png.decode_blob(data) if png
      data = Base64.strict_decode64(data) if base64

      OuterResponse.new(MessagePack.unpack(data))
    end

    OUTER_RESPONSE_FIELDS = %i[publicEncryptionKey sig sig2 msg challengeId].freeze
    class OuterResponse < Struct.new(*OUTER_RESPONSE_FIELDS, keyword_init: true)
      def to_msgpack(out = "")
        to_h.to_msgpack(out)
      end

      # Use our key to open the response. This is akin to unsealing
      def open(private_encryption_key)
        # Use the public key in the box, and the provided private key to derive a new key. And open the box with it.
        public_encryption_key = RbNaCl::PublicKey.new(publicEncryptionKey)
        box = RbNaCl::SimpleBox.from_keypair(public_encryption_key, private_encryption_key)
        opened = box.open(msg)
        inner = InnerResponse.new(MessagePack.unpack(opened))

        # Now that we've opened the box, we can verify that the internal key matches the external signature.
        public_signing_key = OpenSSL::PKey::EC.new(inner.publicSigningKey)
        raise "invalid signature" unless Krypto::Ec.verify(public_signing_key, sig, opened)

        # If we don't have a signature 2 or a public signing key 2, return what we have
        if (sig2.nil? || sig2.empty?) && (inner.publicSigningKey2.nil? || inner.publicSigningKey2.empty?)
          return inner
        end

        # have key but no signature
        if sig2.nil? || sig2.empty?
          raise "have public siging key 2, but no signature 2"
        end

        # have signature but no key
        if inner.publicSigningKey2.nil? || inner.publicSigningKey2.empty?
          raise "have signature 2, but no public signing key 2"
        end

        # now verify signature 2
        public_signing_key_2 = OpenSSL::PKey::EC.new(inner.publicSigningKey2)
        raise "invalid signature" unless Krypto::Ec.verify(public_signing_key_2, sig2, opened)

        inner
      end
    end

    INNER_RESPONSE_FIELDS = %i[publicSigningKey publicSigningKey2 challengeData responseData timestamp].freeze
    class InnerResponse < Struct.new(*INNER_RESPONSE_FIELDS, keyword_init: true)
      def to_msgpack(out = "")
        to_h.to_msgpack(out)
      end
    end
  end
end
