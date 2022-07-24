require "test_helper"

require "securerandom"

class TestAes < Minitest::Test
  KEY1 = Krypto::Aes.random_key.freeze
  KEY2 = Krypto::Aes.random_key.freeze
  MESSAGES = {
    a: "a",
    hello: "Hello World",
    rand1: SecureRandom.bytes(1),
    rand30: SecureRandom.bytes(30),
    rand31: SecureRandom.bytes(31),
    rand32: SecureRandom.bytes(32),
    rand33: SecureRandom.bytes(33),
    rand254: SecureRandom.bytes(254),
    rand255: SecureRandom.bytes(255),
    rand256: SecureRandom.bytes(256),
    rand257: SecureRandom.bytes(257)
  }.freeze

  def setup
  end

  MESSAGES.each do |name, message|
    define_method("test_encryption_roundtrip: #{name}") do
      ciphertext = Krypto::Aes.encrypt(KEY1, nil, message)
      plaintext = Krypto::Aes.decrypt(KEY1, nil, ciphertext)

      assert_equal(message, plaintext)
      refute_equal(plaintext, ciphertext)

      assert_raises { Krypto::Aes.decrypt(KEY1, "wrong", ciphertext) }
      assert_raises { Krypto::Aes.decrypt(KEY2, nil, ciphertext) }
    end

    define_method("test_encryption_roundtrip_with_auth: #{name}") do
      auth_data = SecureRandom.bytes(32)
      ciphertext = Krypto::Aes.encrypt(KEY1, auth_data, message)
      plaintext = Krypto::Aes.decrypt(KEY1, auth_data, ciphertext)

      assert_equal(message, plaintext)
      refute_equal(plaintext, ciphertext)

      assert_raises { Krypto::Aes.decrypt(KEY1, "wrong", ciphertext) }
      assert_raises { Krypto::Aes.decrypt(KEY1, nil, ciphertext) }
      assert_raises { Krypto::Aes.decrypt(KEY2, nil, ciphertext) }
    end
  end
end
