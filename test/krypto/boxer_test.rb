require "test_helper"

require "securerandom"

class TestKryptoBoxer < Minitest::Test
  ALICEKEY = Krypto::Rsa.random_key.freeze
  BOBKEY = Krypto::Rsa.random_key.freeze
  MALLORYKEY = Krypto::Rsa.random_key.freeze

  ALICEBOX = Krypto::Boxer.new(ALICEKEY, BOBKEY).freeze
  BOBBOX = Krypto::Boxer.new(BOBKEY, ALICEKEY).freeze
  BARE_BOBBOX = Krypto::Boxer.new(BOBKEY).freeze
  MALLORYBOX = Krypto::Boxer.new(MALLORYKEY, ALICEKEY).freeze
  BARE_MALLORYBOX = Krypto::Boxer.new(MALLORYKEY).freeze

  MESSAGES = {
    a: "a",
    hello: "Hello World",
    rand32: SecureRandom.bytes(32),
    rand256: SecureRandom.bytes(256),
    rand4096: SecureRandom.bytes(4096)
  }.freeze

  MESSAGES.each do |name, message|
    define_method("test_can_decode: #{name}") do
      box = ALICEBOX.encode(SecureRandom.uuid, message)

      assert_equal(message, BOBBOX.decode(box))
      assert_equal(message, BOBBOX.decode_unverified(box))
      assert_equal(message, BARE_BOBBOX.decode_unverified(box))
    end

    define_method("test_cannot_decode: #{name}") do
      box = ALICEBOX.encode(SecureRandom.uuid, message)

      assert_raises { BARE_BOBBOX.decode(box) }

      assert_raises { MALLORYBOX.decode(box) }
      assert_raises { MALLORYBOX.decode_unverified(box) }
      assert_raises { BARE_MALLORYBOX.decode(box) }
      assert_raises { BARE_MALLORYBOX.decode_unverified(box) }
    end
  end
end
