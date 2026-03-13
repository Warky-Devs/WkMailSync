package source

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// collectMessages drains the Messages iterator into a slice for test assertions.
func collectMessages(src MailSource, folder Folder) ([]Message, error) {
	var msgs []Message
	var firstErr error
	for msg, err := range src.Messages(folder) {
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		msgs = append(msgs, msg)
	}
	return msgs, firstErr
}

// buildMaildir creates a minimal Maildir structure for testing.
// Returns the root path.
func buildMaildir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, sub := range []string{"cur", "new", "tmp"} {
		os.MkdirAll(filepath.Join(root, sub), 0755)
	}
	return root
}

func writeMaildirMsg(t *testing.T, dir, subdir, filename string, content []byte) {
	t.Helper()
	os.MkdirAll(filepath.Join(dir, subdir), 0755)
	if err := os.WriteFile(filepath.Join(dir, subdir, filename), content, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestNewMaildirSource_Valid(t *testing.T) {
	root := buildMaildir(t)
	src, err := NewMaildirSource(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src == nil {
		t.Fatal("expected non-nil source")
	}
	src.Close()
}

func TestNewMaildirSource_Missing(t *testing.T) {
	_, err := NewMaildirSource("/nonexistent/path/Maildir")
	if err == nil {
		t.Error("expected error for missing path")
	}
}

func TestNewMaildirSource_NotDir(t *testing.T) {
	f, err := os.CreateTemp("", "notadir")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	_, err = NewMaildirSource(f.Name())
	if err == nil {
		t.Error("expected error for non-directory path")
	}
}

func TestMaildirSource_ListFolders_InboxOnly(t *testing.T) {
	root := buildMaildir(t)
	src, _ := NewMaildirSource(root)

	folders, err := src.ListFolders()
	if err != nil {
		t.Fatal(err)
	}
	if len(folders) != 1 || folders[0].Name != "INBOX" {
		t.Errorf("expected [INBOX], got %v", folders)
	}
}

func TestMaildirSource_ListFolders_Subfolders(t *testing.T) {
	root := buildMaildir(t)
	// Create dot-prefixed subdirectories (Maildir subfolders)
	os.MkdirAll(filepath.Join(root, ".Sent", "cur"), 0755)
	os.MkdirAll(filepath.Join(root, ".Drafts", "cur"), 0755)
	os.MkdirAll(filepath.Join(root, ".Archive.2024", "cur"), 0755)

	src, _ := NewMaildirSource(root)
	folders, err := src.ListFolders()
	if err != nil {
		t.Fatal(err)
	}

	names := make(map[string]bool)
	for _, f := range folders {
		names[f.Name] = true
	}

	if !names["INBOX"] {
		t.Error("INBOX missing")
	}
	if !names["Sent"] {
		t.Error("Sent missing")
	}
	if !names["Drafts"] {
		t.Error("Drafts missing")
	}
	if !names["Archive/2024"] {
		t.Error("Archive/2024 missing (dots should become slashes)")
	}
}

func TestMaildirSource_ListMessages_Empty(t *testing.T) {
	root := buildMaildir(t)
	src, _ := NewMaildirSource(root)

	msgs, err := collectMessages(src, Folder{Name: "INBOX"})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages, got %d", len(msgs))
	}
}

func TestMaildirSource_ListMessages_ReadsContent(t *testing.T) {
	root := buildMaildir(t)
	content := []byte("From: a@b.com\r\nSubject: Test\r\n\r\nBody text")
	// Maildir filename: timestamp.uniquepart.hostname:2,flags
	writeMaildirMsg(t, root, "cur", "1700000000.abc.host:2,S", content)

	src, _ := NewMaildirSource(root)
	msgs, err := collectMessages(src, Folder{Name: "INBOX"})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if string(msgs[0].Content) != string(content) {
		t.Errorf("content mismatch: got %q", msgs[0].Content)
	}
}

func TestMaildirSource_ListMessages_DateFromKey(t *testing.T) {
	root := buildMaildir(t)
	ts := int64(1700000000)
	writeMaildirMsg(t, root, "cur", "1700000000.abc.host:2,", []byte("msg"))

	src, _ := NewMaildirSource(root)
	msgs, _ := collectMessages(src, Folder{Name: "INBOX"})
	if len(msgs) == 0 {
		t.Fatal("no messages")
	}
	if msgs[0].Date.Unix() != ts {
		t.Errorf("Date = %v, want unix %d", msgs[0].Date, ts)
	}
}

func TestMaildirSource_ListMessages_FlagSeen(t *testing.T) {
	root := buildMaildir(t)
	writeMaildirMsg(t, root, "cur", "1700000001.x.h:2,S", []byte("seen msg"))

	src, _ := NewMaildirSource(root)
	msgs, _ := collectMessages(src, Folder{Name: "INBOX"})
	if len(msgs) == 0 {
		t.Fatal("no messages")
	}
	found := false
	for _, f := range msgs[0].Flags {
		if f == `\Seen` {
			found = true
		}
	}
	if !found {
		t.Errorf("expected \\Seen flag, got %v", msgs[0].Flags)
	}
}

func TestMaildirSource_ListMessages_Subfolder(t *testing.T) {
	root := buildMaildir(t)
	os.MkdirAll(filepath.Join(root, ".Sent", "cur"), 0755)
	os.MkdirAll(filepath.Join(root, ".Sent", "new"), 0755)
	os.MkdirAll(filepath.Join(root, ".Sent", "tmp"), 0755)
	content := []byte("sent message")
	writeMaildirMsg(t, root, ".Sent/cur", "1700000002.y.h:2,", content)

	src, _ := NewMaildirSource(root)
	msgs, err := collectMessages(src, Folder{Name: "Sent"})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message in Sent, got %d", len(msgs))
	}
}

func TestParseDateFromKey(t *testing.T) {
	cases := []struct {
		key  string
		want time.Time
	}{
		{"1700000000.abc.host", time.Unix(1700000000, 0)},
		{"1700000000.abc.host:2,S", time.Unix(1700000000, 0)},
		{"notanumber.abc.host", time.Time{}},
		{"", time.Time{}},
	}
	for _, tc := range cases {
		got := parseDateFromKey(tc.key)
		if !got.Equal(tc.want) {
			t.Errorf("parseDateFromKey(%q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

