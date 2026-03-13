package source

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/emersion/go-maildir"
)

type MaildirSource struct {
	path string
}

func NewMaildirSource(path string) (*MaildirSource, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("maildir path %s: %v", path, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("maildir path %s is not a directory", path)
	}
	return &MaildirSource{path: path}, nil
}

func (s *MaildirSource) ListFolders() ([]Folder, error) {
	entries, err := os.ReadDir(s.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read maildir: %v", err)
	}

	folders := []Folder{{Name: "INBOX"}}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			folderName := strings.TrimPrefix(name, ".")
			folderName = strings.ReplaceAll(folderName, ".", "/")
			folders = append(folders, Folder{Name: folderName})
		}
	}

	return folders, nil
}

func (s *MaildirSource) ListMessages(folder Folder) ([]Message, error) {
	var dirPath string
	if folder.Name == "INBOX" {
		dirPath = s.path
	} else {
		maildirName := "." + strings.ReplaceAll(folder.Name, "/", ".")
		dirPath = filepath.Join(s.path, maildirName)
	}

	dir := maildir.Dir(dirPath)
	msgs, err := dir.Messages()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to list maildir messages: %v", err)
	}

	var messages []Message
	for _, msg := range msgs {
		m, err := s.readMaildirMessage(msg)
		if err != nil {
			continue
		}
		messages = append(messages, m)
	}

	return messages, nil
}

func (s *MaildirSource) readMaildirMessage(msg *maildir.Message) (Message, error) {
	rc, err := msg.Open()
	if err != nil {
		return Message{}, fmt.Errorf("failed to open message %s: %v", msg.Key(), err)
	}
	defer rc.Close()

	content, err := io.ReadAll(rc)
	if err != nil {
		return Message{}, fmt.Errorf("failed to read message %s: %v", msg.Key(), err)
	}

	flags := msg.Flags()
	imapFlags := maildirFlagsToIMAP(flags)

	key := msg.Key()
	date := parseDateFromKey(key)
	if date.IsZero() {
		filePath := msg.Filename()
		if info, err2 := os.Stat(filePath); err2 == nil {
			date = info.ModTime()
		}
	}

	messageID := fmt.Sprintf("<%s@maildir>", key)

	return Message{
		MessageID: messageID,
		Date:      date,
		Flags:     imapFlags,
		Content:   content,
	}, nil
}

func (s *MaildirSource) Close() error {
	return nil
}

func parseDateFromKey(key string) time.Time {
	parts := strings.SplitN(key, ".", 2)
	if len(parts) < 1 {
		return time.Time{}
	}
	var ts int64
	if _, err := fmt.Sscanf(parts[0], "%d", &ts); err != nil || ts <= 0 {
		return time.Time{}
	}
	return time.Unix(ts, 0)
}

func maildirFlagsToIMAP(flags []maildir.Flag) []string {
	var result []string
	for _, f := range flags {
		switch f {
		case maildir.FlagSeen:
			result = append(result, `\Seen`)
		case maildir.FlagReplied:
			result = append(result, `\Answered`)
		case maildir.FlagFlagged:
			result = append(result, `\Flagged`)
		case maildir.FlagDraft:
			result = append(result, `\Draft`)
		case maildir.FlagTrashed:
			result = append(result, `\Deleted`)
		}
	}
	return result
}
