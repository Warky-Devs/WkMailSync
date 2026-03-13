package output

import (
	"archive/zip"
	"os"
	"strings"
	"testing"
)

func TestZipOutput_WriteAndClose(t *testing.T) {
	dir := t.TempDir()

	z, err := NewZipOutput(dir, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}

	content := []byte("From: a@b.com\r\nSubject: Hi\r\n\r\nBody")
	if err := z.WriteMessage("INBOX", "20240101_120000_Hi_a.eml", content); err != nil {
		t.Fatal(err)
	}
	if err := z.WriteMessage("Sent", "20240102_080000_Re_b.eml", []byte("reply")); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}

	// Verify zip file exists
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 zip file, got %d", len(entries))
	}
	zipPath := dir + "/" + entries[0].Name()
	if !strings.HasSuffix(zipPath, ".zip") {
		t.Errorf("expected .zip extension, got %s", zipPath)
	}
	if !strings.HasPrefix(entries[0].Name(), "user@example.com_") {
		t.Errorf("zip filename should start with sanitized username, got %s", entries[0].Name())
	}

	// Verify zip contents
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	names := make(map[string]bool)
	for _, f := range r.File {
		names[f.Name] = true
	}
	if !names["INBOX/20240101_120000_Hi_a.eml"] {
		t.Error("INBOX entry missing from zip")
	}
	if !names["Sent/20240102_080000_Re_b.eml"] {
		t.Error("Sent entry missing from zip")
	}
}

func TestZipOutput_ExistsAlwaysFalse(t *testing.T) {
	dir := t.TempDir()
	z, err := NewZipOutput(dir, "u")
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()

	z.WriteMessage("INBOX", "msg.eml", []byte("x"))
	if z.Exists("msg.eml") {
		t.Error("ZipOutput.Exists should always return false")
	}
}

func TestZipOutput_ZipContentMatchesInput(t *testing.T) {
	dir := t.TempDir()
	z, err := NewZipOutput(dir, "testuser")
	if err != nil {
		t.Fatal(err)
	}

	want := []byte("From: x@y.com\r\nSubject: S\r\n\r\nContent here")
	z.WriteMessage("INBOX", "msg.eml", want)
	z.Close()

	entries, _ := os.ReadDir(dir)
	r, _ := zip.OpenReader(dir + "/" + entries[0].Name())
	defer r.Close()

	for _, f := range r.File {
		rc, _ := f.Open()
		buf := make([]byte, len(want))
		rc.Read(buf)
		rc.Close()
		if string(buf) != string(want) {
			t.Errorf("zip content mismatch: got %q, want %q", buf, want)
		}
	}
}
