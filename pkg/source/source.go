package source

import "time"

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
	ListMessages(folder Folder) ([]Message, error)
	Close() error
}
