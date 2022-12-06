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

counterparty_signingkey = if testcase["CounterpartySigningKey"]
  OpenSSL::PKey::RSA.new(testcase["CounterpartySigningKey"])
end

counterparty_encryptionkey = if testcase["CounterpartyEncryptionKey"]
  OpenSSL::PKey::RSA.new(testcase["CounterpartyEncryptionKey"])
end

boxer = Krypto::Boxer.new(key, counterparty_signingkey, counterparty_encryptionkey)

case cmd
when "encode"
  testcase["Ciphertext"] = boxer.encode(testcase["ResponseTo"], testcase["Plaintext"])
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "sign"
  testcase["Ciphertext"] = boxer.sign(testcase["ResponseTo"], testcase["Plaintext"])
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "decode"
  testcase["Plaintext"] = boxer.decode(testcase["Ciphertext"]).data
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "decodeunverified"
  testcase["Plaintext"] = boxer.decode_unverified(testcase["Ciphertext"]).data
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "decodepng"
  testcase["Plaintext"] = boxer.decode_png(File.read(testcase["PngFile"])).data
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "verify"
  testcase["Plaintext"] = boxer.decode(testcase["Ciphertext"]).signedtext
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "verifyunverified"
  testcase["Plaintext"] = boxer.decode_unverified(testcase["Ciphertext"]).signedtext
  File.write(outfile, Base64.strict_encode64(MessagePack.pack(testcase)))
when "spew"
  pp testcase
else
  puts "What are we doing here?"
  exit(1)
end
