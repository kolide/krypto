require "test_helper"

require "openssl"

class TestKryptoNacler < Minitest::Test
  ALICEKEY = OpenSSL::PKey::EC.generate("prime256v1")
  BOBKEY = OpenSSL::PKey::EC.generate("prime256v1")

  ALICENACLER = Krypto::Nacler.new(ALICEKEY, BOBKEY.public_key)
  BOBNACLER = Krypto::Nacler.new(BOBKEY, ALICEKEY.public_key)

  MESSAGE_TO_SEAL = "this is the plaintext of the sealed message"

  def test_alice_seal_bob_open do
    cipertext = ALICENACLER.seal(MESSAGE_TO_SEAL)
    assert_equal(MESSAGE_TO_SEAL, BOBNACLER.open(cipertext))
  end

  def test_bob_seal_alice_open do
    cipertext = BOBNACLER.seal(MESSAGE_TO_SEAL)
    assert_equal(MESSAGE_TO_SEAL, ALICENACLER.open(cipertext))
  end
end
