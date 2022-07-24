require "test_helper"

require "openssl"
require "securerandom"

class TestRsa < Minitest::Test
  KEY1 = Krypto::Rsa.random_key.freeze
  KEY2 = Krypto::Rsa.random_key.freeze
  MESSAGES = {
    a: "a",
    hello: "Hello World",
    rand1: SecureRandom.bytes(1),
    rand32: SecureRandom.bytes(32),
    rand64: SecureRandom.bytes(64)
  }.freeze

  def setup
  end

  MESSAGES.each do |name, message|
    define_method("test_encryption_roundtrip: #{name}") do
      ciphertext = Krypto::Rsa.encrypt(KEY1.public_key, message)
      plaintext = Krypto::Rsa.decrypt(KEY1, ciphertext)

      assert_equal(message, plaintext)
      refute_equal(plaintext, ciphertext)

      assert_raises { Krypto::Rsa.decrypt(KEY2, ciphertext) }
    end

    define_method("test_signatures: #{name}") do
      signature = Krypto::Rsa.sign(KEY1, message)

      assert(Krypto::Rsa.verify(KEY1, signature, message))
      refute(Krypto::Rsa.verify(KEY2, message, signature))
    end
  end
end
