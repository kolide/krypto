package krypto

import (
	"image"
	"image/png"
	"io"
	"math"
)

const (
	bytesPerPixel = 4 // RGBA
)

func ToPng(w io.Writer, data []byte) error {
	pixelCount := divCeil(len(data), bytesPerPixel)

	width := int(math.Floor(math.Sqrt(float64(pixelCount))))
	height := divCeil(pixelCount, width)

	stride := width * bytesPerPixel

	pixels := make([]uint8, width*height*bytesPerPixel)
	_ = copy(pixels, data)

	img := &image.RGBA{
		Pix:    pixels,
		Stride: int(stride),
		Rect:   image.Rectangle{image.Point{0, 0}, image.Point{width, height}},
	}

	return png.Encode(w, img)
}

func FromPng() ([]byte, error) {
	return nil, nil
}

func divCeil(numerator, denominator int) int {
	quotient, remainder := numerator/denominator, numerator%denominator

	if remainder > 0 {
		return quotient + 1
	}

	return quotient
}
