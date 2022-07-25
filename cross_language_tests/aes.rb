#!/usr/bin/env ruby

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "base64"
require "msgpack"
require "krypto"

args = ARGV

cmd = args.shift
testcase = MessagePack.unpack(Base64.strict_decode64(File.read(args.shift)))
outfile = args.shift

case cmd
when nil, ""
  puts "What are we doing here?"
  exit(1)
when "encrypt"
  testcase["Ciphertext"] = Krypto::Aes.encrypt(testcase["Key"], testcase["AuthData"], testcase["Plaintext"])
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "decrypt"
  testcase["Plaintext"] = Krypto::Aes.decrypt(testcase["Key"], testcase["AuthData"], testcase["Ciphertext"])
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "spew"
  pp testcase
end
