# frozen_string_literal: true

require 'openssl'

module Krypto
  module Aes
    ALGORITHM = 'aes-256-gcm'
    def encrypt(key, auth_data, plaintext)
      cipher = OpenSSL::Cipher.new(ALGORITHM)
      cipher.encrypt

      cipher.key = key
      iv = cipher.random_iv
      cipher.auth_data = auth_data if auth_data

      ciphertext = cipher.update(plaintext)
      ciphertext += cipher.final

      # Check sizes on the iv and MAC (auth_tag)
      raise "Bad Authentication Tag" unless cipher.auth_tag.size == 16
      raise "Bad IV" unless iv.size == 12

      # It's customary to append the MAC, and go assumes that. It is also
      # customary to prepend the iv.
      return (iv.bytes + ciphertext.bytes + cipher.auth_tag.bytes).pack('c*')
    end
    module_function :encrypt

    def decrypt(key, auth_data, ciphertext)
      decipher = OpenSSL::Cipher.new(ALGORITHM)
      decipher.decrypt

      decipher.key = key

      # Extract the iv and auth_tag from the ciphertext
      decipher.iv = ciphertext.byteslice(0, 12)
      decipher.auth_tag = ciphertext.byteslice(-16, 16)
      sliced = ciphertext.byteslice(12, ciphertext.bytesize - 12 - 16)

      decipher.update(sliced) + decipher.final
    end
    module_function :decrypt
  end
end
