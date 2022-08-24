# frozen_string_literal: true

# Modified png parsing routines from the internet. Thank you
# especially:
#  - https://github.com/wvanbergen/chunky_png
#  - https://gist.github.com/snatchev/1f9dab21f48a49e2240a757b1e7db952

require 'chunky_png'

module Krypto
  class Png
    class BadHeaderError < StandardError; end

    BYTES_PER_PIXEL = 4.freeze
    
    def self.decode(file)
      @img = ChunkyPNG::Image.from_file(file)

      @header = color_to_rgba(@img.pixels[0])

      raise BadHeaderError.new("Missing identifier") unless @header[0].eql?(0x4b) && @header[1].eql?(0x32)

      return case @header[2]
             when 0
               decode0(@header, @img.pixels)
             else
               raise BadHeaderError.new("Unknown format: #{header[3]}")
             end
    end


    def self.color_to_rgba(value)
      [
        ChunkyPNG::Color.r(value),
        ChunkyPNG::Color.g(value),
        ChunkyPNG::Color.b(value),
        ChunkyPNG::Color.a(value),
      ]
    end


    def self.decode0(header, pixels)
      padding_len = header[3]
      data_len = (pixels.size - 1) *  BYTES_PER_PIXEL
      data_len -= padding_len
      
      # This is probably less efficient than iterating over the image,
      # and stopping when we're done. But the bit shift operations are
      # quite cheap, and the maximum amount of padding is small.
      pixels
        .map { |pixel| color_to_rgba(pixel) }
        .flatten
        .slice(BYTES_PER_PIXEL, data_len)
        .pack('C*')
    end
  end
end
