# frozen_string_literal: true

require "base64"
require "krypto/aes"
require "krypto/rsa"
require "msgpack"
require "securerandom"
require "stringio"

module Krypto
  class Boxer
    MAX_BOX_SIZE = 4 * 1024 * 1024

    def initialize(key, counterparty = nil)
      raise "Missing key" unless key
      @key = key
      @fingerprint = ::Krypto::Rsa.fingerprint(key)
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
            sender: @fingerprint
          )
        )
      )
    end

    def sender(data, png: false)
      data = unpng(data) if png
      outer = Outer.new(MessagePack.unpack(data))
      outer.sender
    end

    def decode_unverified(data)
      decode(data, verify: false)
    end

    def decode(data, verify: true, raw: false, png: false)
      data = unpng(data) if png
      data = Base64.strict_decode64(data) unless raw || png
      outer = Outer.new(MessagePack.unpack(data))

      raise "Bag Signature" if verify && !::Krypto::Rsa.verify(@counterparty, outer.signature, outer.inner)

      decode_inner(outer.inner)
    end

    def decode_png(data, verify: true)
      decode(data, verify: verify, raw: true, png: true)
    end

    private

    def unpng(data)
      reader = StringIO.new(data)

      # read past the first 8 header bytes
      # TODO: Verify maybe?
      reader.read(8)

      # Read chunks until the IEND
      chunk_type = nil
      while chunk_type != "IEND"
        length, chunk_type = reader.read(8).unpack("Na4") # gives us length, and the chunk type
        reader.read(length + 4) # fast forward past the length, plus it's checksum
      end

      reader.read(MAX_BOX_SIZE)
    end

    def decode_inner(data)
      inner = Inner.new(MessagePack.unpack(data))

      aeskey = ::Krypto::Rsa.decrypt(@key, inner.key)
      inner.data = ::Krypto::Aes.decrypt(aeskey, nil, inner.ciphertext)

      # zero out uninteresting data
      inner.key = nil
      inner.ciphertext = nil

      inner
    end

    class Inner < Struct.new(*%i[version timestamp key ciphertext requestid responseto sender data], keyword_init: true)
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
