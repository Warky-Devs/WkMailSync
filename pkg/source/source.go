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
}

type Folder struct {
	Name string
}

type MailSource interface {
	ListFolders() ([]Folder, error)
	// Messages streams messages in the folder one at a time.
	// The caller ranges over the iterator; each yield is (Message, error).
	// A non-nil error signals a fatal read failure for that item.
	Messages(folder Folder) iter.Seq2[Message, error]
	Close() error
}
