package source

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
	"github.com/emersion/go-imap"
	imapClient "github.com/emersion/go-imap/client"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/charset"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/unicode"
)

func init() {
	asciiEncoding := unicode.UTF8
	charset.RegisterEncoding("ascii", asciiEncoding)
	charset.RegisterEncoding("us-ascii", asciiEncoding)
	charset.RegisterEncoding("ASCII", asciiEncoding)
	charset.RegisterEncoding("US-ASCII", asciiEncoding)
	charset.RegisterEncoding("windows-1252", charmap.Windows1252)
	charset.RegisterEncoding("WINDOWS-1252", charmap.Windows1252)
	charset.RegisterEncoding("cp1252", charmap.Windows1252)
	charset.RegisterEncoding("CP1252", charmap.Windows1252)
	charset.RegisterEncoding("iso-8859-1", charmap.ISO8859_1)
	charset.RegisterEncoding("ISO-8859-1", charmap.ISO8859_1)
	charset.RegisterEncoding("latin1", charmap.ISO8859_1)
	charset.RegisterEncoding("LATIN1", charmap.ISO8859_1)
}

type IMAPSource struct {
	client  *imapClient.Client
	cfg     config.ServerConfig
	folders []Folder
}

func Connect(cfg config.ServerConfig) (*imapClient.Client, error) {
	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)

	var c *imapClient.Client
	var err error

	if cfg.UseTLS {
		tlsConfig := &tls.Config{ServerName: cfg.Host}
		if cfg.InsecureTLS {
			tlsConfig.InsecureSkipVerify = true
		}
		c, err = imapClient.DialTLS(addr, tlsConfig)
	} else {
		c, err = imapClient.Dial(addr)
	}

	if err != nil {
		return nil, err
	}

	if err := c.Login(cfg.Username, cfg.Password); err != nil {
		c.Logout()
		return nil, err
	}

	return c, nil
}

func NewIMAPSource(cfg config.ServerConfig) (*IMAPSource, error) {
	c, err := Connect(cfg)
	if err != nil {
		return nil, err
	}
	return &IMAPSource{client: c, cfg: cfg}, nil
}

func (s *IMAPSource) Client() *imapClient.Client {
	return s.client
}

func (s *IMAPSource) Reconnect() error {
	if s.client != nil {
		s.client.Logout()
	}
	c, err := Connect(s.cfg)
	if err != nil {
		return fmt.Errorf("failed to reconnect: %v", err)
	}
	s.client = c
	return nil
}

func (s *IMAPSource) EnsureConnected() error {
	if s.client == nil {
		return s.Reconnect()
	}
	if err := s.client.Noop(); err != nil {
		log.Printf("Source connection lost, reconnecting: %v", err)
		return s.Reconnect()
	}
	return nil
}

func (s *IMAPSource) ListFolders() ([]Folder, error) {
	mailboxes := make(chan *imap.MailboxInfo, 10)
	done := make(chan error, 1)
	go func() {
		done <- s.client.List("", "*", mailboxes)
	}()

	var folders []Folder
	for m := range mailboxes {
		folders = append(folders, Folder{Name: m.Name})
	}

	if err := <-done; err != nil {
		return nil, fmt.Errorf("failed to list mailboxes: %v", err)
	}

	return folders, nil
}

func (s *IMAPSource) ListMessages(folder Folder) ([]Message, error) {
	mbox, err := s.client.Select(folder.Name, true)
	if err != nil {
		return nil, fmt.Errorf("failed to select mailbox %s: %v", folder.Name, err)
	}

	if mbox.Messages == 0 {
		return nil, nil
	}

	const batchSize = 100
	var result []Message

	for start := uint32(1); start <= mbox.Messages; start += batchSize {
		end := start + batchSize - 1
		if end > mbox.Messages {
			end = mbox.Messages
		}

		seqset := new(imap.SeqSet)
		seqset.AddRange(start, end)

		messages := make(chan *imap.Message, int(end-start+1)+10)
		done := make(chan error, 1)
		go func() {
			done <- s.client.Fetch(seqset, []imap.FetchItem{
				imap.FetchEnvelope,
				imap.FetchRFC822,
				imap.FetchFlags,
				imap.FetchInternalDate,
			}, messages)
		}()

		var batch []*imap.Message
		for msg := range messages {
			batch = append(batch, msg)
		}

		if err := <-done; err != nil {
			return nil, fmt.Errorf("failed to fetch messages: %v", err)
		}

		for _, msg := range batch {
			if msg.Envelope == nil {
				continue
			}

			content, err := extractRawContent(msg)
			if err != nil {
				log.Printf("  Failed to extract content for message %v: %v", msg.SeqNum, err)
				continue
			}

			messageID := msg.Envelope.MessageId
			if messageID == "" {
				date := msg.InternalDate
				if date.IsZero() && !msg.Envelope.Date.IsZero() {
					date = msg.Envelope.Date
				}
				if date.IsZero() {
					date = time.Now()
				}
				subject := msg.Envelope.Subject
				if subject == "" {
					subject = "(no subject)"
				}
				h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d-%d", subject, date.Unix(), msg.SeqNum)))
				messageID = fmt.Sprintf("<%x@wkmailsync.generated>", h[:8])
			}

			from := ""
			if len(msg.Envelope.From) > 0 {
				if msg.Envelope.From[0].PersonalName != "" {
					from = msg.Envelope.From[0].PersonalName
				} else if msg.Envelope.From[0].MailboxName != "" {
					from = msg.Envelope.From[0].MailboxName
				}
			}

			date := msg.InternalDate
			if date.IsZero() && !msg.Envelope.Date.IsZero() {
				date = msg.Envelope.Date
			}
			if date.IsZero() {
				date = time.Now()
			}

			result = append(result, Message{
				MessageID: messageID,
				Subject:   msg.Envelope.Subject,
				From:      from,
				Date:      date,
				Flags:     msg.Flags,
				Content:   content,
			})
		}
	}

	return result, nil
}

func (s *IMAPSource) Close() error {
	if s.client != nil {
		return s.client.Logout()
	}
	return nil
}

func extractRawContent(msg *imap.Message) ([]byte, error) {
	if msg.Body == nil {
		return nil, fmt.Errorf("message body is nil")
	}

	var msgBody io.Reader
	for section, body := range msg.Body {
		if section != nil && section.Specifier == imap.TextSpecifier {
			msgBody = body
			break
		}
	}
	if msgBody == nil {
		for _, body := range msg.Body {
			if body != nil {
				msgBody = body
				break
			}
		}
	}
	if msgBody == nil {
		return nil, fmt.Errorf("no valid body section found")
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, msgBody); err != nil {
		return nil, fmt.Errorf("failed to read message body: %v", err)
	}

	return buf.Bytes(), nil
}

func ParseMessageWithFallback(msgBody io.Reader, messageID string) (*message.Entity, error) {
	entity, err := message.Read(msgBody)
	if err == nil {
		return entity, nil
	}

	if strings.Contains(err.Error(), "charset") ||
		strings.Contains(err.Error(), "unknown charset") ||
		strings.Contains(err.Error(), "malformed MIME") ||
		strings.Contains(err.Error(), "malformed header") ||
		strings.Contains(err.Error(), "invalid header") ||
		strings.Contains(err.Error(), "bad header") {
		log.Printf("  Parsing error for message %s, will use raw copy: %v", messageID, err)
		return nil, fmt.Errorf("charset_error: %w", err)
	}

	log.Printf("  Message parsing error for message %s, attempting raw copy: %v", messageID, err)
	return nil, fmt.Errorf("charset_error: %w", err)
}
