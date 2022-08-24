package krypto

import (
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"math"
)

const (
	bytesPerPixel  = 4  // RGBA
	maxWidthPixels = 63 // Converted to bytes is less than 0xFF
)

func ToPng(w io.Writer, data []byte) error {
	dataPlusHeader := len(data) + bytesPerPixel

	pixelCount := divCeil(dataPlusHeader, bytesPerPixel)

	width := min(maxWidthPixels, int(math.Floor(math.Sqrt(float64(pixelCount)))))
	height := divCeil(pixelCount, width)
	stride := width * bytesPerPixel

	canvas := width * height * bytesPerPixel
	paddingLen := canvas - dataPlusHeader

	header := []byte{0x4b, 0x32, 0, uint8(paddingLen)}

	img := &image.NRGBA{
		Pix:    append(header, data...),
		Stride: stride,
		Rect:   image.Rectangle{image.Point{0, 0}, image.Point{width, height}},
	}

	encoder := &png.Encoder{}
	return encoder.Encode(w, img)
}

func FromPng(r io.Reader, w io.Writer) error {
	imgRaw, _, err := image.Decode(r)
	if err != nil {
		return fmt.Errorf("decoding png: %w", err)
	}

	img, ok := imgRaw.(*image.NRGBA)
	if !ok {
		return errors.New("image is not nrgba")
	}

	if len(img.Pix) < 4 {
		return errors.New("image too small")
	}

	if img.Pix[0] != 0x4b || img.Pix[1] != 0x32 || img.Pix[2] != 0 {
		return errors.New("image missing header")
	}

	paddingLen := img.Pix[3]
	if _, err := w.Write(img.Pix[4 : len(img.Pix)-int(paddingLen)]); err != nil {
		return fmt.Errorf("writing data: %w", err)
	}

	return nil
}

// divCeil divides and then takes the ceiling. This could be done with several calls to math,
// but that would entail a lot of float64 conversions.
func divCeil(numerator, denominator int) int {
	quotient, remainder := numerator/denominator, numerator%denominator

	if remainder > 0 {
		return quotient + 1
	}

	return quotient
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
