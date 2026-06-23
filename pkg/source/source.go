package source

import (
	"iter"
	"time"
)

type Message struct {
	MessageID string
	Subject   string
	From      string
	Date      time.Time
	Flags     []string
	Content   []byte
	UID       uint32
}

type Folder struct {
	Name string
}

type MailSource interface {
	ListFolders() ([]Folder, error)
	// Messages streams messages in the folder one at a time.
	// afterUID, when non-zero, skips messages with UID ≤ afterUID (IMAP only;
	// non-IMAP sources ignore it and yield all messages).
	Messages(folder Folder, afterUID uint32) iter.Seq2[Message, error]
	Close() error
}
