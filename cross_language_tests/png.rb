#!/usr/bin/env ruby

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "base64"
require "krypto"

args = ARGV

cmd = args.shift
pngfile = args.shift
outfile = args.shift

case cmd
when "decode-file"
  data = Krypto::Png.decode_file(pngfile)
  File.write(outfile, Base64.strict_encode64(data))
when "decode-blob"
  blob = File.read(pngfile)
  data = Krypto::Png.decode_blob(blob)
  File.write(outfile, Base64.strict_encode64(data))
when "decode-io"
  io = File.open(pngfile)
  data = Krypto::Png.decode_io(io)
  File.write(outfile, Base64.strict_encode64(data))

else
  puts "What are we doing here?"
  exit(1)
end
