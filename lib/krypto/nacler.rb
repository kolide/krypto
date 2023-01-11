# frozen_string_literal: true

require "rbnacl"
require "openssl"

module Krypto
  class Nacler
    def initialize(key, counterparty)
      raise "Missing key" unless key
      @key = key
      raise "Missing counter party" unless counterparty
      @counterparty = counterparty

      shared_key = OpenSSL::Digest::SHA256.digest(@key.dh_compute_key(@counterparty))
      @box = RbNaCl::SimpleBox.from_secret_key(shared_key)
    end

    def seal(plaintext)
      @box.encrypt(plaintext)
    end

    def open(ciphertext)
      @box.decrypt(ciphertext)
    end
  end
end
