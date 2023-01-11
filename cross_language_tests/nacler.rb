#!/usr/bin/env ruby

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "base64"
require "krypto"
require "msgpack"

args = ARGV

cmd = args.shift
testcase = MessagePack.unpack(Base64.strict_decode64(File.read(args.shift)))

key = OpenSSL::PKey::EC.new(testcase["Key"])
counterparty = OpenSSL::PKey::EC.new(testcase["Counterparty"])
nacler = Krypto::Nacler.new(key, counterparty.public_key)

case cmd
when "seal"
  puts(Base64.strict_encode64(nacler.seal(testcase["Plaintext"])))
when "open"
  puts(Base64.strict_encode64(nacler.open(testcase["Ciphertext"])))
else
  puts "What are we doing here?"
  exit(1)
end
