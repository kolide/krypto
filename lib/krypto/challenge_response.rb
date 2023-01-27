# frozen_string_literal: true

require "rbnacl"
require "msgpack"
require "openssl"

module Krypto
  class ChallengeResponse
    def self.unmarshal(data, png: false, base64: true)
      data = ::Krypto::Png.decode_blob(data) if png
      data = Base64.strict_decode(data) if base64

      OuterResponse.new(MessagePack.unpack(data))
    end

    OUTER_RESPONSE_FIELDS = %i[publicEncryptionKey sig msg challengeId].freeze
    class OuterResponse < Struct.new(*OUTER_RESPONSE_FIELDS, keyword_init: true)
      def to_msgpack(out = "")
        to_h.to_msgpack(out)
      end

      # Use our key to open the response. This is akin to unsealing
      def open(private_encryption_key, png: false)
        # Use the public key in the box, and the provided private key to derive a new key. And open the box with it.
        public_encryption_key = RbNaCl::PublicKey.new(publicEncryptionKey)
        box = RbNaCl::SimpleBox.from_keypair(public_encryption_key, private_encryption_key)
        opened = box.open(msg)
        inner = InnerResponse.new(MessagePack.unpack(opened))

        # Now that we've opened the box, we can verify that the internal key matches the external signature.
        public_signing_key = OpenSSL::PKey::EC.new(inner.publicSigningKey)
        raise "invalid signature" unless Krypto::Ec.verify(public_signing_key, sig, opened)

        inner
      end
    end

    INNER_RESPONSE_FIELDS = %i[publicSigningKey challengeData responseData timeStamp].freeze
    class InnerResponse < Struct.new(*INNER_RESPONSE_FIELDS, keyword_init: true)
      def to_msgpack(out = "")
        to_h.to_msgpack(out)
      end
    end
  end
end
