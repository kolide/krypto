# frozen_string_literal: true

require "openssl"
module Krypto
  module Ec
    def random_key
      OpenSSL::PKey::EC.generate("prime256v1")
    end
    module_function :random_key

    def sign(key, data)
      key.sign(OpenSSL::Digest.new("SHA256"), data)
    end
    module_function :sign

    def verify(key, signature, data)
      key.dsa_verify_asn1(OpenSSL::Digest.new("SHA256").digest(data), signature)
    end
    module_function :verify
  end
end
