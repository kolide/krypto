#!/usr/bin/env ruby

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "base64"
require "krypto"
require "msgpack"
require "openssl"

args = ARGV

cmd = args.shift

testFilePath = args.shift
testFileDir = File.dirname(testFilePath)
testcase = MessagePack.unpack(Base64.strict_decode64(File.read(testFilePath)))

privateEncrytionKeyPath = testFileDir + "/private_encryption_key"

challenge = Krypto::Challenge.new

case cmd
when "generate"
  # write the private encryption key to the test directory to retrieve in later tests
  key = OpenSSL::PKey::EC.new(testcase["RubyPrivateSigningKey"])
  result = challenge.generate(key, testcase["ChallengeData"])
  File.write(privateEncrytionKeyPath, Base64.strict_encode64(result[1]))

  # return the challenge
  puts(
    Base64.strict_encode64(
      MessagePack.pack(
        result[0]
      )
    )
  )

when "respond"
  signingKey = OpenSSL::PKey::EC.generate("prime256v1")
  counterparty = OpenSSL::PKey::EC.new(testcase["ChallengerPublicKey"])
  outerChallenge = Krypto::Challenge::OuterChallenge.new(MessagePack.unpack(testcase["ChallengePack"]))
  data = testcase["ResponseData"]

  puts(
    Base64.strict_encode64(
      MessagePack.pack(
        challenge.respond(
          signingKey,
          counterparty,
          outerChallenge,
          data
        )
      )
    )
  )

when "open_response"
  # read the encryption key from generate test
  privateEncryptionKeyBytes = Base64.strict_decode64(File.read(privateEncrytionKeyPath))
  privateEncryptionKey = RbNaCl::PrivateKey.new(privateEncryptionKeyBytes)

  outerResponse = Krypto::Challenge::OuterResponse.new(MessagePack.unpack(testcase["ResponsePack"]))

  puts(
    Base64.strict_encode64(
      MessagePack.pack(
        challenge.open_response(
          privateEncryptionKey,
          outerResponse
        )
      )
    )
  )

else
  puts "What are we doing here?"
  exit(1)
end
