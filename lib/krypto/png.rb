# frozen_string_literal: true

# Modified png parsing routines from the internet. Thank you
# especially:
#  - https://github.com/wvanbergen/chunky_png
#  - https://gist.github.com/snatchev/1f9dab21f48a49e2240a757b1e7db952

require "chunky_png"

module Krypto
  class Png
    class BadHeaderError < StandardError; end

    USABLE_BYTES_PER_PIXEL = 3
    PIXELS_IN_HEADER = 2

    def self.decode_io(io)
      ds = ChunkyPNG::Datastream.from_io(io)
      img = ChunkyPNG::Image.from_datastream(ds)

      process(img)
    end

    def self.decode_blob(blob)
      img = ChunkyPNG::Image.from_blob(blob)
      process(img)
    end

    def self.decode_file(file)
      img = ChunkyPNG::Image.from_file(file)
      process(img)
    end

    def self.process(img)
      header = color_to_rgba(img.pixels[0])

      raise BadHeaderError.new("Missing identifier") unless header[0].eql?(0x4b) && header[1].eql?(0x32)

      case header[2]
      when 0
        decode0(img.pixels)
      else
        raise BadHeaderError.new("Unknown format: #{header[3]}")
      end
    end

    def self.color_to_rgba(value)
      [
        ChunkyPNG::Color.r(value),
        ChunkyPNG::Color.g(value),
        ChunkyPNG::Color.b(value)
      ]
    end

    def self.decode0(pixels)
      # This uses the chunky_png integer weirdness and bitshifts out our 24bit number.
      data_len = pixels[1] >> 8
      pixels_needed = divCeil(data_len, USABLE_BYTES_PER_PIXEL)

      pixels
        .slice(PIXELS_IN_HEADER, pixels_needed)
        .map { |pixel| color_to_rgba(pixel) }
        .flatten
        .slice(0, data_len)
        .pack("C*")
    end

    def self.divCeil(numerator, denominator)
      quotient = numerator / denominator
      remainder = numerator % denominator

      quotient += 1 if remainder > 0

      quotient
    end
  end
end
