#!/usr/bin/env ruby

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "base64"
require "krypto"

args = ARGV

cmd = args.shift
pngfile = args.shift # File.read(args.shift)
outfile = args.shift

case cmd
when "decode"
  data = Krypto::Png.decode(pngfile)
  File.write(outfile, Base64.strict_encode64(data))
else
  puts "What are we doing here?"
  exit(1)
end
