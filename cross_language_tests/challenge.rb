#!/usr/bin/env ruby

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "base64"
require "krypto"
require "msgpack"
require "openssl"

args = ARGV

cmd = args.shift

test_file_path = args.shift
test_file_dir = File.dirname(test_file_path)
test_case = MessagePack.unpack(Base64.strict_decode64(File.read(test_file_path)))

private_encryption_key_path = test_file_dir + "/private_encryption_key"

case cmd
when "generate"
  # write the private encryption key to the test directory to retrieve in later tests
  key = OpenSSL::PKey::EC.new(test_case["RubyPrivateSigningKey"])
  result = Krypto::Challenge.generate(key, test_case["ChallengeId"], test_case["ChallengeData"], test_case["RequestData"], Time.now)
  File.write(private_encryption_key_path, Base64.strict_encode64(result[1]))

  # return the challenge
  puts(
    Base64.strict_encode64(
      MessagePack.pack(
        result[0]
      )
    )
  )

when "respond"
  signing_key = OpenSSL::PKey::EC.generate("prime256v1")
  signing_key_2 = OpenSSL::PKey::EC.generate("prime256v1")
  counter_party = OpenSSL::PKey::EC.new(test_case["ChallengerPublicKey"])
  outer_challenge = Krypto::Challenge::OuterChallenge.new(MessagePack.unpack(test_case["ChallengePack"]))

  if !outer_challenge.verify(counter_party)
    raise "challenge verification failed"
  end

  data = test_case["ResponseData"]

  puts(
    Base64.strict_encode64(
      MessagePack.pack(
        outer_challenge.respond(
          signing_key,
          signing_key_2,
          data
        )
      )
    )
  )

when "open_response_png"
  # read the encryption key from generate test
  private_encryption_key_bytes = Base64.strict_decode64(File.read(private_encryption_key_path))
  private_encryption_key = RbNaCl::PrivateKey.new(private_encryption_key_bytes)
  challenge_response = Krypto::ChallengeResponse.unmarshal(test_case["ResponsePack"], png: true, base64: false)

  puts(
    Base64.strict_encode64(
      MessagePack.pack(
        challenge_response.open(private_encryption_key)
      )
    )
  )

else
  puts "What are we doing here?"
  exit(1)
end
