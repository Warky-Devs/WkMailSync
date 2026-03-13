package output

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type ZipOutput struct {
	file     *os.File
	writer   *zip.Writer
	username string
}

func NewZipOutput(outputDir, username string) (*ZipOutput, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %v", err)
	}
	timestamp := time.Now().Format("20060102_150405")
	zipName := fmt.Sprintf("%s_%s.zip", sanitizeFilename(username), timestamp)
	zipPath := filepath.Join(outputDir, zipName)

	f, err := os.Create(zipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create zip file: %v", err)
	}

	return &ZipOutput{
		file:     f,
		writer:   zip.NewWriter(f),
		username: username,
	}, nil
}

func (z *ZipOutput) WriteMessage(folder, filename string, content []byte) error {
	entryPath := fmt.Sprintf("%s/%s", sanitizeFilename(folder), filename)
	w, err := z.writer.Create(entryPath)
	if err != nil {
		return fmt.Errorf("failed to create zip entry: %v", err)
	}
	if _, err := w.Write(content); err != nil {
		return fmt.Errorf("failed to write zip entry: %v", err)
	}
	return nil
}

func (z *ZipOutput) Exists(key string) bool {
	return false
}

func (z *ZipOutput) Close() error {
	if err := z.writer.Close(); err != nil {
		return err
	}
	return z.file.Close()
}
