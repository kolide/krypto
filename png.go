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
	bytesPerPixel       = 4  // RGBA
	usableBytesPerPixel = 3  // RGB (no alpha)
	maxWidthPixels      = 63 // Converted to bytes is less than 0xFF
	pixelsInHeader      = 2
	alphaValue          = 0xFF

	// Limit size to prevent garbage from filling memory
	V0MaxSize = 4 * 1024 * 1024
)

func ToPngNoMaxSize(w io.Writer, data []byte) error {
	pixelCount := divCeil(len(data), usableBytesPerPixel)
	pixelCount = pixelCount + pixelsInHeader + 1

	width := min(maxWidthPixels, int(math.Floor(math.Sqrt(float64(pixelCount)))))
	height := divCeil(pixelCount, width)
	stride := width * bytesPerPixel

	canvasSize := width * height * bytesPerPixel
	pixelBytes := make([]byte, canvasSize)

	// Setup header
	pixelBytes[0] = 0x4b
	pixelBytes[1] = 0x32
	pixelBytes[2] = 0x0
	pixelBytes[3] = alphaValue

	copy(pixelBytes[4:], intToInt24(len(data)))
	pixelBytes[7] = alphaValue

	pixelBytesStart := pixelsInHeader * bytesPerPixel
	for i := 0; i < len(data); i += usableBytesPerPixel {
		lastData := min(len(data), i+usableBytesPerPixel)

		copy(pixelBytes[pixelBytesStart:], data[i:lastData])
		pixelBytes[pixelBytesStart+3] = alphaValue

		pixelBytesStart += bytesPerPixel
	}

	img := &image.NRGBA{
		Pix:    pixelBytes,
		Stride: stride,
		Rect:   image.Rectangle{image.Point{0, 0}, image.Point{width, height}},
	}

	encoder := &png.Encoder{}
	return encoder.Encode(w, img)
}

func ToPng(w io.Writer, data []byte) error {
	dataSize := len(data)
	if dataSize > V0MaxSize {
		return fmt.Errorf("data too big: %d is bigger than %d", dataSize, V0MaxSize)
	}

	return ToPngNoMaxSize(w, data)
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

	if len(img.Pix) < pixelsInHeader*bytesPerPixel {
		return errors.New("image too small")
	}

	if img.Pix[0] != 0x4b || img.Pix[1] != 0x32 || img.Pix[2] != 0 {
		return errors.New("image missing header")
	}

	dataLen := int24ToInt(img.Pix[4:7])
	dataStart := pixelsInHeader * bytesPerPixel

	if dataLen == 0 {
		return nil
	}

	dataSeen := 0
	for i := dataStart; i < len(img.Pix); i += 1 {
		// Skip alpha channels
		if i%4 == 3 {
			continue
		}

		if _, err := w.Write([]byte{img.Pix[i]}); err != nil {
			return fmt.Errorf("writing data: %w", err)
		}

		dataSeen += 1

		if dataSeen >= dataLen {
			break
		}

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

func int24ToInt(i24 []byte) int {
	return int(uint32(i24[2]) | uint32(i24[1])<<8 | uint32(i24[0])<<16)
}

func intToInt24(i int) []byte {
	return []byte{
		uint8(i >> 16),
		uint8(i >> 8),
		uint8(i),
	}
}
