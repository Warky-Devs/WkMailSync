package source

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"log"
	"net/http"
	"net/url"
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

// xoauth2Client implements the SASL XOAUTH2 mechanism for IMAP.
type xoauth2Client struct {
	username string
	token    string
}

func (x *xoauth2Client) Start() (string, []byte, error) {
	ir := []byte("user=" + x.username + "\x01auth=Bearer " + x.token + "\x01\x01")
	return "XOAUTH2", ir, nil
}

// Next acknowledges a server challenge (error JSON on auth failure) so the server can reply with NO.
func (x *xoauth2Client) Next(_ []byte) ([]byte, error) {
	return []byte{}, nil
}

func fetchAccessToken(cfg *config.OAuth2Config) (string, error) {
	resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"refresh_token": {cfg.RefreshToken},
		"grant_type":    {"refresh_token"},
	})
	if err != nil {
		return "", fmt.Errorf("token refresh: %v", err)
	}
	defer resp.Body.Close()
	var tr struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode token response: %v", err)
	}
	if tr.Error != "" {
		return "", fmt.Errorf("token refresh %s: %s", tr.Error, tr.ErrorDesc)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("empty access token in response")
	}
	return tr.AccessToken, nil
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

	if cfg.OAuth2 != nil {
		token, err := fetchAccessToken(cfg.OAuth2)
		if err != nil {
			c.Logout()
			return nil, fmt.Errorf("OAuth2 token: %v", err)
		}
		if err := c.Authenticate(&xoauth2Client{username: cfg.Username, token: token}); err != nil {
			c.Logout()
			return nil, fmt.Errorf("OAuth2 auth: %v", err)
		}
	} else {
		if err := c.Login(cfg.Username, cfg.Password); err != nil {
			c.Logout()
			return nil, err
		}
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

var imapFetchItems = []imap.FetchItem{
	imap.FetchUid,
	imap.FetchEnvelope,
	imap.FetchRFC822,
	imap.FetchFlags,
	imap.FetchInternalDate,
}

func (s *IMAPSource) Messages(folder Folder, afterUID uint32) iter.Seq2[Message, error] {
	return func(yield func(Message, error) bool) {
		mbox, err := s.client.Select(folder.Name, true)
		if err != nil {
			yield(Message{}, fmt.Errorf("failed to select mailbox %s: %v", folder.Name, err))
			return
		}
		if mbox.Messages == 0 {
			return
		}

		if afterUID > 0 {
			s.fetchByUID(folder, afterUID, yield)
			return
		}
		s.fetchBySeq(mbox.Messages, yield)
	}
}

// fetchByUID fetches only messages with UID > afterUID using UID SEARCH + UID FETCH.
func (s *IMAPSource) fetchByUID(folder Folder, afterUID uint32, yield func(Message, error) bool) {
	criteria := &imap.SearchCriteria{Uid: new(imap.SeqSet)}
	criteria.Uid.AddRange(afterUID+1, 0)
	uids, err := s.client.UidSearch(criteria)
	if err != nil {
		yield(Message{}, fmt.Errorf("UID SEARCH %s: %v", folder.Name, err))
		return
	}
	if len(uids) == 0 {
		return
	}

	const batchSize = 100
	for i := 0; i < len(uids); i += batchSize {
		end := i + batchSize
		if end > len(uids) {
			end = len(uids)
		}
		seqset := new(imap.SeqSet)
		for _, uid := range uids[i:end] {
			seqset.AddNum(uid)
		}
		ch := make(chan *imap.Message, end-i+10)
		done := make(chan error, 1)
		go func() {
			done <- s.client.UidFetch(seqset, imapFetchItems, ch)
		}()
		var batch []*imap.Message
		for msg := range ch {
			batch = append(batch, msg)
		}
		if err := <-done; err != nil {
			yield(Message{}, fmt.Errorf("UID FETCH %s: %v", folder.Name, err))
			return
		}
		for _, msg := range batch {
			if !yieldImapMessage(msg, yield) {
				return
			}
		}
	}
}

// fetchBySeq fetches all messages using sequence-number batches (used on first run).
func (s *IMAPSource) fetchBySeq(total uint32, yield func(Message, error) bool) {
	const batchSize = 100
	for start := uint32(1); start <= total; start += batchSize {
		end := start + batchSize - 1
		if end > total {
			end = total
		}
		seqset := new(imap.SeqSet)
		seqset.AddRange(start, end)

		ch := make(chan *imap.Message, int(end-start+1)+10)
		done := make(chan error, 1)
		go func() {
			done <- s.client.Fetch(seqset, imapFetchItems, ch)
		}()
		var batch []*imap.Message
		for msg := range ch {
			batch = append(batch, msg)
		}
		if err := <-done; err != nil {
			yield(Message{}, fmt.Errorf("failed to fetch messages: %v", err))
			return
		}
		for _, msg := range batch {
			if !yieldImapMessage(msg, yield) {
				return
			}
		}
	}
}

func yieldImapMessage(msg *imap.Message, yield func(Message, error) bool) bool {
	if msg == nil || msg.Envelope == nil {
		return true
	}
	content, err := extractRawContent(msg)
	if err != nil {
		log.Printf("  Failed to extract content for message %v: %v", msg.SeqNum, err)
		return true
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

	return yield(Message{
		UID:       msg.Uid,
		MessageID: messageID,
		Subject:   msg.Envelope.Subject,
		From:      from,
		Date:      date,
		Flags:     msg.Flags,
		Content:   content,
	}, nil)
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
