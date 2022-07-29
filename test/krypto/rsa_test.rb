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

  FINGERPRINTS = {
    "public.pem": "80:61:16:6c:86:e8:9f:a2:91:49:b4:75:f8:46:1a:ae:9d:a6:72:e9:dd:4a:c4:f5:b3:07:d1:3a:99:ba:d7:71",
    "private.pem": "80:61:16:6c:86:e8:9f:a2:91:49:b4:75:f8:46:1a:ae:9d:a6:72:e9:dd:4a:c4:f5:b3:07:d1:3a:99:ba:d7:71"
  }.freeze

  FINGERPRINTS.each do |filename, expected|
    define_method("test_fingerprint: #{filename}") do
      filepath = File.expand_path("../../test-data/#{filename}", __dir__)
      key = Krypto::Rsa.key_from_pem(filepath)
      actual = Krypto::Rsa.fingerprint(key)

      assert_equal(expected, actual)
    end
  end
end
