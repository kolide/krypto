require "test_helper"
require "openssl"
require "base64"

class TestKryptoChallenge < Minitest::Test
  CHALLENGER_KEY = Krypto::Ec.random_key
  CHALLENGER_PUB = OpenSSL::PKey::EC.new(CHALLENGER_KEY.public_to_der)

  RESPONDER_KEY = Krypto::Ec.random_key
  RESPONDER_PUB = OpenSSL::PKey::EC.new(RESPONDER_KEY.public_to_der)

  RESPONDER_KEY_2 = Krypto::Ec.random_key
  RESPONDER_PUB_2 = OpenSSL::PKey::EC.new(RESPONDER_KEY.public_to_der)

  # Challenge ID and challenge data are used internally by the challenger
  CHALLENGE_ID = SecureRandom.uuid
  CHALLENGE_DATA = SecureRandom.uuid

  # request and response are expect to be examined and tinkered with
  REQUEST_DATA = SecureRandom.uuid
  RESPONDER_DATA = SecureRandom.uuid

  def test_challenge
    # First, the challenger generates a challenge, and stashes the private key somewhere for future retrivial
    challenge, private_encryption_key = ::Krypto::Challenge.generate(CHALLENGER_KEY, CHALLENGE_ID, CHALLENGE_DATA, REQUEST_DATA, Time.now.to_i)

    # Next, the responder, having recieved the challenge, verifies it, and examines it.
    assert(challenge.verify(CHALLENGER_PUB))
    assert_equal(REQUEST_DATA, challenge.request_data)

    # satisfied, the responder now crafts a response with a single signing key.
    response = challenge.respond(RESPONDER_KEY, nil, RESPONDER_DATA)
    validate_response(private_encryption_key, response)

    # satisfied, the responder now crafts a response with 2 signing keys.
    response = challenge.respond(RESPONDER_KEY, RESPONDER_KEY_2, RESPONDER_DATA)
    validate_response(private_encryption_key, response)
  end

  def validate_response(private_encryption_key, response)
    # The challenger uses the challengeId to find the ephemeral encrytion key, and opens the response.
    assert_equal(CHALLENGE_ID, response.challengeId)

    # The challenger uses the challengeId to find the ephemeral encrytion key, and opens the response.
    assert_equal(CHALLENGE_ID, response.challengeId)

    opened = response.open(private_encryption_key)
    refute_nil(opened)

    # We've passed the encryption, does the challenge data match what we expect?
    # (in real usage, this would be a rails authenticator)
    assert_equal(CHALLENGE_DATA, opened.challengeData)

    # And finally, the challenger does something with the results.
    assert_equal(RESPONDER_DATA, opened.responseData)
  end

  def test_verify_with_key_bytes
    key = Krypto::Ec.random_key
    data = SecureRandom.uuid
    sig = Krypto::Ec.sign(key, data)

    # make sure we handle b64 der
    Krypto::ChallengeResponse::OuterResponse.verify_with_key_bytes(Base64.strict_encode64(key.public_to_der), sig, data)

    # make sure we handle pem
    Krypto::ChallengeResponse::OuterResponse.verify_with_key_bytes(key.public_to_pem, sig, data)
  end
end
