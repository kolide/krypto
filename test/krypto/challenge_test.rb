require "test_helper"
require "openssl"

class TestKryptoChallenge < Minitest::Test
  CHALLENGER_KEY = OpenSSL::PKey::EC.generate("prime256v1")
  RESPONDER_KEY = OpenSSL::PKey::EC.generate("prime256v1")

  CHALLENGE_DATA = "this is a challenge"
  RESPONDER_DATA = "this is some responder data"

  CHALLENGE_ID = "this is a challenge id"

  def test_challenge
    challenge, private_encryption_key = ::Krypto::Challenge.generate(CHALLENGER_KEY, CHALLENGE_ID, CHALLENGE_DATA)
    challenge_packed = Base64.strict_encode64(MessagePack.pack(challenge))

    challenger_public_key = OpenSSL::PKey::EC.new(CHALLENGER_KEY.public_to_pem)
    response = ::Krypto::Challenge.respond(RESPONDER_KEY, challenger_public_key, challenge_packed) { RESPONDER_DATA }

    assert_equal(response.challengeId, CHALLENGE_ID)

    response_packed = MessagePack.pack(response)
    opened_response = ::Krypto::Challenge.open_response(private_encryption_key, response_packed)

    assert_equal(CHALLENGE_DATA, opened_response.challengeData)
    assert_equal(RESPONDER_DATA, opened_response.responseData)
  end
end
