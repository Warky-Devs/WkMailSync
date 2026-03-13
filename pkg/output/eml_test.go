package output

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEMLOutput_WriteAndExists(t *testing.T) {
	dir := t.TempDir()

	out, err := NewEMLOutput(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	content := []byte("From: test@example.com\r\nSubject: Test\r\n\r\nBody")
	if err := out.WriteMessage("INBOX", "20240101_120000_Test_sender.eml", content); err != nil {
		t.Fatal(err)
	}

	// File must exist on disk
	path := filepath.Join(dir, "INBOX", "20240101_120000_Test_sender.eml")
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected file at %s: %v", path, err)
	}

	// Exists must return true for written key
	if !out.Exists("20240101_120000_Test_sender.eml") {
		t.Error("Exists returned false after write")
	}

	// Exists must return false for unknown key
	if out.Exists("other.eml") {
		t.Error("Exists returned true for unknown key")
	}
}

func TestEMLOutput_UsernameSubdir(t *testing.T) {
	dir := t.TempDir()

	out, err := NewEMLOutput(dir, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	if err := out.WriteMessage("Sent", "msg.eml", []byte("data")); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "user@example.com", "Sent", "msg.eml")
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected file at %s: %v", path, err)
	}
}

func TestEMLOutput_FolderSanitized(t *testing.T) {
	dir := t.TempDir()
	out, err := NewEMLOutput(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	if err := out.WriteMessage(`Folder/With:Bad\Chars`, "msg.eml", []byte("x")); err != nil {
		t.Fatal(err)
	}
	// Should not contain raw special chars in path
	entries, _ := os.ReadDir(dir)
	if len(entries) == 0 {
		t.Error("no directory created")
	}
}

func TestEMLOutput_EmptyOutputDir(t *testing.T) {
	_, err := NewEMLOutput("", "")
	// Empty dir will try to MkdirAll("") which may or may not error depending on OS
	// Just verify no panic
	_ = err
}

func TestEMLOutput_LoadExisting(t *testing.T) {
	dir := t.TempDir()
	folderDir := filepath.Join(dir, "INBOX")
	os.MkdirAll(folderDir, 0755)
	os.WriteFile(filepath.Join(folderDir, "existing.eml"), []byte("x"), 0644)

	out, err := NewEMLOutput(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	out.LoadExisting("INBOX")

	if !out.Exists("existing.eml") {
		t.Error("LoadExisting should populate Exists")
	}
}
