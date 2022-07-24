# frozen_string_literal: true

require 'openssl'

module Krypto
  module Rsa
    def encrypt(key, message)
      key.encrypt(message, rsa_padding_mode: "oaep")
    end
    module_function :encrypt

    def decrypt(key, ciphertext)
      key.decrypt(ciphertext, rsa_padding_mode: "oaep")
    end
    module_function :decrypt

    def sign(key, data)
      key.sign("SHA256", data, { rsa_padding_mode: "pss" })
    end
    module_function :sign

    def verify(key, signature, data)
      key.verify("SHA256", signature, data, { rsa_padding_mode: "pss" })
    end
    module_function :verify
  end
end
