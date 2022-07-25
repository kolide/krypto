#!/usr/bin/env ruby

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "base64"
require "msgpack"
require "krypto"

args = ARGV

cmd = args.shift
testcase = MessagePack.unpack(Base64.strict_decode64(File.read(args.shift)))
outfile = args.shift

public_key = OpenSSL::PKey::RSA.new(testcase["Public"])
private_key = OpenSSL::PKey::RSA.new(testcase["Private"])

case cmd
when "encrypt"
  testcase["Ciphertext"] = Krypto::Rsa.encrypt(public_key, testcase["Plaintext"])
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "decrypt"
  testcase["Plaintext"] = Krypto::Rsa.decrypt(private_key, testcase["Ciphertext"])
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "sign"
  testcase["Signature"] = Krypto::Rsa.sign(private_key, testcase["Plaintext"])
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "verify"
  testcase["Verified"] = Krypto::Rsa.verify(public_key, testcase["Signature"], testcase["Plaintext"])
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "spew"
  pp testcase
else
  puts "What are we doing here?"
  exit(1)
end