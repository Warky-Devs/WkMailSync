package output

type MailOutput interface {
	WriteMessage(folder, filename string, content []byte) error
	Exists(key string) bool
	Close() error
}
