#!/usr/bin/env ruby

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "base64"
require "msgpack"
require "krypto"

args = ARGV

cmd = args.shift
testcase = MessagePack.unpack(Base64.strict_decode64(File.read(args.shift)))
outfile = args.shift

key = OpenSSL::PKey::RSA.new(testcase["Key"])
counterparty = if testcase["Counterparty"]
                 OpenSSL::PKey::RSA.new(testcase["Counterparty"])
               else
                 nil
               end
boxer = Krypto::Boxer.new(key, counterparty)

case cmd
when nil, ""
  puts "What are we doing here?"
  exit(1)
when "encode"
  testcase["Ciphertext"] = box.encode(testcase["ResponseTo"], testcase["Plaintext"])
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "decode"
  testcase["Plaintext"] = boxer.decode(testcase["Ciphertext"])
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "decodeunverified"
  testcase["Plaintext"] = boxer.decode_unverified(testcase["Ciphertext"])
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "spew"
  pp testcase
end
