# frozen_string_literal: true

require "rbnacl"
require "base64"
require "openssl"

module Krypto
  class Nacler
    def initialize(key, counterparty)
      raise "Missing key" unless key
      @key = key
      raise "Missing counter party" unless counterparty
      @counterparty = counterparty
    end

    def seal(plaintext)
      shared = @key.dh_compute_key(@counterparty)
      shared_key = OpenSSL::Digest::SHA256.digest(shared)
      box = RbNaCl::SimpleBox.from_secret_key(shared_key)
      ciphertext = box.encrypt(plaintext)
      Base64.strict_encode64(ciphertext)
    end

    def open(ciphertext)
      shared = @key.dh_compute_key(@counterparty)
      shared_key = OpenSSL::Digest::SHA256.digest(shared)
      ciphertext = Base64.strict_decode64(ciphertext)
      box = RbNaCl::SimpleBox.from_secret_key(shared_key)
      box.decrypt(ciphertext)
    end
  end
end
