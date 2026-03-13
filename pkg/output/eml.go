package output

import (
	"fmt"
	"os"
	"path/filepath"
)

type EMLOutput struct {
	outputDir string
	existing  map[string]bool
}

// NewEMLOutput creates an EML output rooted at outputDir.
// username is optional; when non-empty, messages are written under outputDir/username/.
func NewEMLOutput(outputDir, username string) (*EMLOutput, error) {
	root := outputDir
	if username != "" {
		root = filepath.Join(outputDir, sanitizeFilename(username))
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %v", err)
	}
	return &EMLOutput{
		outputDir: root,
		existing:  make(map[string]bool),
	}, nil
}

func (e *EMLOutput) LoadExisting(folder string) error {
	dir := filepath.Join(e.outputDir, sanitizeFilename(folder))
	files, err := filepath.Glob(filepath.Join(dir, "*.eml"))
	if err != nil {
		return nil
	}
	for _, f := range files {
		e.existing[filepath.Base(f)] = true
	}
	return nil
}

func (e *EMLOutput) WriteMessage(folder, filename string, content []byte) error {
	dir := filepath.Join(e.outputDir, sanitizeFilename(folder))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create folder dir: %v", err)
	}
	filePath := filepath.Join(dir, filename)
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}
	e.existing[filename] = true
	return nil
}

func (e *EMLOutput) Exists(key string) bool {
	return e.existing[key]
}

func (e *EMLOutput) Close() error {
	return nil
}
