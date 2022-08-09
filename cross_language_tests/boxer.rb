#!/usr/bin/env ruby

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "base64"
require "krypto"
require "msgpack"

args = ARGV

cmd = args.shift
testcase = MessagePack.unpack(Base64.strict_decode64(File.read(args.shift)))
outfile = args.shift

key = OpenSSL::PKey::RSA.new(testcase["Key"])
counterparty = if testcase["Counterparty"]
  OpenSSL::PKey::RSA.new(testcase["Counterparty"])
end
boxer = Krypto::Boxer.new(key, counterparty)

case cmd
when "encode"
  testcase["Ciphertext"] = boxer.encode(testcase["ResponseTo"], testcase["Plaintext"])
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "decode"
  testcase["Plaintext"] = boxer.decode(testcase["Ciphertext"])
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "decodeunverified"
  testcase["Plaintext"] = boxer.decode_unverified(testcase["Ciphertext"])
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "decodepng"
  testcase["Plaintext"] = boxer.decode_png(File.read(testcase["PngFile"]))
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "spew"
  pp testcase
else
  puts "What are we doing here?"
  exit(1)
end
