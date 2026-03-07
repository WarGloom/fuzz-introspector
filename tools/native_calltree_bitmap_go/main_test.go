package main

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func TestRenderBitmapWritesExpectedColors(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "bitmap.png")
	job := bitmapJob{
		JobID:      "bitmap.png",
		OutputPath: outputPath,
		ColorList:  []string{"red", "gold"},
	}

	if err := renderBitmap(job, 10, 2); err != nil {
		t.Fatalf("renderBitmap() error = %v", err)
	}

	file, err := os.Open(outputPath)
	if err != nil {
		t.Fatalf("Open(%q) error = %v", outputPath, err)
	}
	defer file.Close()
	img, err := png.Decode(file)
	if err != nil {
		t.Fatalf("png.Decode() error = %v", err)
	}

	left := img.At(0, 0)
	r, g, _, _ := left.RGBA()
	if r == 0 || g != 0 {
		t.Fatalf("left pixel = (%d,%d), want red-dominant", r, g)
	}

	right := img.At(9, 0)
	r, g, _, _ = right.RGBA()
	if r == 0 || g == 0 {
		t.Fatalf("right pixel = (%d,%d), want gold-like", r, g)
	}
}

func TestColorNameToRGBADefaultsUnknownToRed(t *testing.T) {
	colorValue := colorNameToRGBA("mystery")
	if colorValue.R != 0xff || colorValue.G != 0x00 || colorValue.B != 0x00 {
		t.Fatalf("colorNameToRGBA() = %#v, want red fallback", colorValue)
	}
}
