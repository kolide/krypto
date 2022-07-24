# frozen_string_literal: true

require 'openssl'

module Krypto
  module Rsa
    SIGN_OPTS = { rsa_padding_mode: 'pss' }.freeze

    def encrypt(key, message)
      key.encrypt(message, rsa_padding_mode: 'oaep')
    end
    module_function :encrypt

    def decrypt(key, ciphertext)
      key.decrypt(ciphertext, rsa_padding_mode: 'oaep')
    end
    module_function :decrypt

    def sign(key, data)
      key.sign('SHA256', data, SIGN_OPTS)
    end
    module_function :sign

    def verify(key, signature, data)
      key.verify('SHA256', signature, data, SIGN_OPTS)
    end
    module_function :verify
  end
end
