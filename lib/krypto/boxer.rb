# frozen_string_literal: true

require "krypto/rsa"
require "krypto/aes"
require "msgpack"
require "securerandom"
require "base64"

module Krypto
  class Boxer
    def initialize(key, counterparty = nil)
      @key = key
      @counterparty = counterparty
    end

    def encode(in_response_to, data)
      aeskey = ::Krypto::Aes.random_key
      aeskey_enc = ::Krypto::Rsa.encrypt(@counterparty, aeskey)
      ciphertext = ::Krypto::Aes.encrypt(aeskey, nil, data)

      inner = MessagePack.pack(
        Inner.new(
          version: 1,
          timestamp: Time.now.to_i,
          key: aeskey_enc,
          ciphertext: ciphertext,
          requestid: SecureRandom.uuid,
          responseto: in_response_to
        )
      )

      Base64.strict_encode64(
        MessagePack.pack(
          Outer.new(
            inner: inner,
            signature: ::Krypto::Rsa.sign(@key, inner),
            sender: "me"
          )
        )
      )
    end

    def decode_unverified(data)
      outer = Outer.new(MessagePack.unpack(Base64.strict_decode64(data)))
      decode_inner(outer.inner)
    end

    def decode(data)
      outer = Outer.new(MessagePack.unpack(Base64.strict_decode64(data)))

      raise "Bag Signature" unless ::Krypto::Rsa.verify(@counterparty, outer.signature, outer.inner)

      decode_inner(outer.inner)
    end

    private

    def decode_inner(data)
      inner = Inner.new(MessagePack.unpack(data))

      aeskey = ::Krypto::Rsa.decrypt(@key, inner.key)
      ::Krypto::Aes.decrypt(aeskey, nil, inner.ciphertext)
    end

    class Inner < Struct.new(*%i[version timestamp key ciphertext requestid responseto], keyword_init: true)
      def to_msgpack(out = "")
        to_h.to_msgpack(out)
      end
    end
    private_constant :Inner

    class Outer < Struct.new(*%i[inner signature sender], keyword_init: true)
      def to_msgpack(out = "")
        to_h.to_msgpack(out)
      end
    end
    private_constant :Outer
  end
end
