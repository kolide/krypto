# frozen_string_literal: true

require "openssl"

module Krypto
  module Rsa
    SIGN_OPTS = {rsa_padding_mode: "pss"}.freeze

    def random_key
      OpenSSL::PKey::RSA.generate(2048)
    end
    module_function :random_key

    def encrypt(key, message)
      key.encrypt(message, rsa_padding_mode: "oaep")
    end
    module_function :encrypt

    def decrypt(key, ciphertext)
      key.decrypt(ciphertext, rsa_padding_mode: "oaep")
    end
    module_function :decrypt

    def sign(key, data)
      key.sign("SHA256", data, SIGN_OPTS)
    end
    module_function :sign

    def verify(key, signature, data)
      key.verify("SHA256", signature, data, SIGN_OPTS)
    end
    module_function :verify

    def fingerprint(key)
      der = key.public_key.to_der
      OpenSSL::Digest::SHA256.hexdigest(der).scan(/../).join(":")
    end
    module_function :fingerprint

    def key_from_pem(infile)
      OpenSSL::PKey::RSA.new(File.read(infile))
    end
    module_function :key_from_pem
  end
end
