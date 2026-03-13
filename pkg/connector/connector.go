package connector

type MailUser struct {
	Domain      string
	Username    string
	HomeDir     string
	MaildirPath string
}

type VirtualminConnector interface {
	ListDomains() ([]string, error)
	ListUsers(domain string) ([]MailUser, error)
	Close() error
}
