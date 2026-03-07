package main

import (
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const schemaVersion = 1

type inputPayload struct {
	SchemaVersion int         `json:"schema_version"`
	Width         int         `json:"width"`
	Height        int         `json:"height"`
	Jobs          []bitmapJob `json:"jobs"`
}

type bitmapJob struct {
	JobID      string   `json:"job_id"`
	OutputPath string   `json:"output_path"`
	ColorList  []string `json:"color_list"`
}

type outputPayload struct {
	Status  string      `json:"status"`
	Results []jobResult `json:"results"`
	Error   string      `json:"error,omitempty"`
}

type jobResult struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

func colorNameToRGBA(name string) color.RGBA {
	switch name {
	case "red":
		return color.RGBA{R: 0xff, A: 0xff}
	case "gold":
		return color.RGBA{R: 0xff, G: 0xd7, A: 0xff}
	case "yellow":
		return color.RGBA{R: 0xff, G: 0xff, A: 0xff}
	case "greenyellow":
		return color.RGBA{R: 0xad, G: 0xff, B: 0x2f, A: 0xff}
	case "lawngreen":
		return color.RGBA{R: 0x7c, G: 0xfc, A: 0xff}
	default:
		return color.RGBA{R: 0xff, A: 0xff}
	}
}

func renderBitmap(job bitmapJob, width int, height int) error {
	colors := job.ColorList
	if len(colors) == 0 {
		colors = []string{"red"}
	}
	if width <= 0 {
		width = 1500
	}
	if height <= 0 {
		height = 250
	}

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	columnsPerColor := float64(width) / float64(len(colors))
	for index, colorName := range colors {
		startX := int(float64(index) * columnsPerColor)
		endX := int(float64(index+1) * columnsPerColor)
		if endX > width {
			endX = width
		}
		fill := colorNameToRGBA(colorName)
		for x := startX; x < endX; x++ {
			for y := 0; y < height; y++ {
				img.Set(x, y, fill)
			}
		}
	}

	if err := os.MkdirAll(filepath.Dir(job.OutputPath), 0o755); err != nil {
		return err
	}
	file, err := os.Create(job.OutputPath)
	if err != nil {
		return err
	}
	defer file.Close()
	return png.Encode(file, img)
}

func writeJSON(payload outputPayload, exitCode int) {
	_ = json.NewEncoder(os.Stdout).Encode(payload)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func run() error {
	rawInput, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read stdin: %w", err)
	}

	var payload inputPayload
	if err := json.Unmarshal(rawInput, &payload); err != nil {
		return fmt.Errorf("json parse error: %w", err)
	}
	if payload.SchemaVersion != schemaVersion {
		return fmt.Errorf("unsupported schema_version: %d", payload.SchemaVersion)
	}
	if payload.Width == 0 {
		payload.Width = 1500
	}
	if payload.Height == 0 {
		payload.Height = 250
	}

	results := make([]jobResult, len(payload.Jobs))
	var wg sync.WaitGroup
	for idx, job := range payload.Jobs {
		wg.Add(1)
		go func(index int, current bitmapJob) {
			defer wg.Done()
			if err := renderBitmap(current, payload.Width, payload.Height); err != nil {
				results[index] = jobResult{JobID: current.JobID, Status: "error", Error: err.Error()}
				return
			}
			results[index] = jobResult{JobID: current.JobID, Status: "ok"}
		}(idx, job)
	}
	wg.Wait()

	status := "success"
	for _, result := range results {
		if result.Status != "ok" {
			status = "partial"
			break
		}
	}
	writeJSON(outputPayload{Status: status, Results: results}, 0)
	return nil
}

func main() {
	if err := run(); err != nil {
		writeJSON(outputPayload{Status: "error", Error: err.Error()}, 1)
	}
}
