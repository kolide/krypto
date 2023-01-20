require "test_helper"
require "openssl"

class TestKryptoChallenge < Minitest::Test
  CHALLENGER_KEY = OpenSSL::PKey::EC.generate("prime256v1")
  RESPONDER_KEY = OpenSSL::PKey::EC.generate("prime256v1")

  CHALLENGE_DATA = "this is a challenge"
  RESPONDER_DATA = "this is some responder data"

  def test_challenge
    challenger = Krypto::Challenge.new
    challenge, privateEncryptionKey = challenger.generate(CHALLENGER_KEY, CHALLENGE_DATA)

    challengerPublic = OpenSSL::PKey::EC.new(CHALLENGER_KEY.public_to_pem)
    response = challenger.respond(RESPONDER_KEY, challengerPublic, challenge, RESPONDER_DATA)

    openedResponse = challenger.open_response(privateEncryptionKey, response)

    assert_equal(CHALLENGE_DATA, openedResponse.challengeData)
    assert_equal(RESPONDER_DATA, openedResponse.responseData)
  end
end
