require "test_helper"

require "securerandom"

class TestKryptoBoxer < Minitest::Test
  ALICEKEY = Krypto::Rsa.random_key.freeze
  BOBKEY = Krypto::Rsa.random_key.freeze
  MALLORYKEY = Krypto::Rsa.random_key.freeze

  ALICEBOX = Krypto::Boxer.new(ALICEKEY, BOBKEY).freeze
  BOBBOX =  Krypto::Boxer.new(BOBKEY, ALICEKEY).freeze
  BARE_BOBBOX =  Krypto::Boxer.new(BOBKEY).freeze
  MALLORYBOX =  Krypto::Boxer.new(MALLORYKEY, ALICEKEY).freeze
  BARE_MALLORYBOX =  Krypto::Boxer.new(MALLORYKEY).freeze
  
  MESSAGES = {
    a: "a",
    hello: "Hello World",
    rand32: SecureRandom.bytes(32),
    rand256: SecureRandom.bytes(256),
    rand4096: SecureRandom.bytes(4096),
  }.freeze
  MESSAGEBOXES = {}
  
  def setup
  end

  MESSAGES.each do |name, message|

    define_method("test_encryption: #{name}") do
      MESSAGEBOXES[name] = ALICEBOX.encode(SecureRandom.uuid, message)
    end
    
    define_method("test_can_decode: #{name}") do
      assert_equal(message, BOBBOX.decode(MESSAGEBOXES[name]))
      assert_equal(message, BOBBOX.decode_unverified(MESSAGEBOXES[name]))
      assert_equal(message, BARE_BOBBOX.decode_unverified(MESSAGEBOXES[name]))
    end

    define_method("test_cannot_decode: #{name}") do
      assert_raises { BARE_BOBBOX.decode(MESSAGEBOXES[name]) }

      assert_raises { MALLORYBOX.decode(MESSAGEBOXES[name]) }
      assert_raises { MALLORYBOX.decode_unverified(MESSAGEBOXES[name]) }
      assert_raises { BARE_MALLORYBOX.decode(MESSAGEBOXES[name]) }
      assert_raises { BARE_MALLORYBOX.decode_unverified(MESSAGEBOXES[name]) }
    end
  end
end
