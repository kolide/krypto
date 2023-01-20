require "test_helper"
require "openssl"

class TestKryptoChallenge < Minitest::Test
  CHALLENGER_KEY = OpenSSL::PKey::EC.generate("prime256v1")
  RESPONDER_KEY = OpenSSL::PKey::EC.generate("prime256v1")

  CHALLENGE_DATA = "this is a challenge"
  RESPONDER_DATA = "this is some responder data"

  def test_challenge
    challenger = Krypto::Challenge.new
    challenge, private_encryption_key = challenger.generate(CHALLENGER_KEY, CHALLENGE_DATA)

    challenger_public_key = OpenSSL::PKey::EC.new(CHALLENGER_KEY.public_to_pem)
    response = challenger.respond(RESPONDER_KEY, challenger_public_key, challenge, RESPONDER_DATA)

    opened_response = challenger.open_response(private_encryption_key, response)

    assert_equal(CHALLENGE_DATA, opened_response.challengeData)
    assert_equal(RESPONDER_DATA, opened_response.responseData)
  end
end
