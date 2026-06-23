package monitor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
	"github.com/emersion/go-imap"
	imapClient "github.com/emersion/go-imap/client"
)

// connectionWorker manages one IMAP connection that rotates through a slice of
// folders, IDLEing on each for idleWindow before moving to the next.
// This keeps the total number of simultaneous connections bounded by
// max_connections regardless of how many folders exist.
type connectionWorker struct {
	id      int
	folders []string
	cfg     config.MonitorConfig
	state   *StateStore
	webhook *WebhookClient
	tokens  *TokenSource
	newMsg  func(folder string)
}

func (w *connectionWorker) label() string {
	return fmt.Sprintf("conn#%d", w.id)
}

// run is the outer reconnect loop with exponential backoff.
func (w *connectionWorker) run(ctx context.Context) {
	backoff := 5 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := w.runLoop(ctx)
		if ctx.Err() != nil {
			return
		}
		log.Printf("[%s] disconnected (%v), reconnecting in %v…", w.label(), err, backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		if backoff < 5*time.Minute {
			backoff *= 2
		}
	}
}

func (w *connectionWorker) runLoop(ctx context.Context) error {
	c, rawConn, err := w.dial()
	if err != nil {
		return fmt.Errorf("connect: %v", err)
	}

	// Closing rawConn immediately unblocks any in-flight IMAP I/O (Idle, Select,
	// Fetch, …) without waiting for a server response — essential for fast shutdown.
	closeDone := make(chan struct{})
	defer close(closeDone)
	defer rawConn.Close()
	go func() {
		select {
		case <-ctx.Done():
			rawConn.Close()
		case <-closeDone:
		}
	}()

	// imapUpdates must be large enough that go-imap's reader goroutine never
	// blocks on a send — if it does, c.loggedOut never closes and shutdown hangs.
	// The drainer goroutine below keeps the channel continuously drained and
	// coalesces signals into the single-item hasUpdate channel used by idleFolder.
	// The drainer exits when c.LoggedOut() closes (reader goroutine done), which
	// guarantees the reader goroutine can always complete its send and exit.
	imapUpdates := make(chan imapClient.Update, 256)
	c.Updates = imapUpdates
	hasUpdate := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-imapUpdates:
				select {
				case hasUpdate <- struct{}{}:
				default:
				}
			case <-c.LoggedOut():
				return
			}
		}
	}()

	// Catch up all assigned folders before entering the IDLE rotation.
	for _, folder := range w.folders {
		if ctx.Err() != nil {
			return nil
		}
		if err := w.initFolder(c, folder); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}

	log.Printf("[%s] IDLE active on %d folder(s): %s",
		w.label(), len(w.folders), strings.Join(w.folders, ", "))

	idleWindow := time.Duration(w.cfg.IdleWindowSec) * time.Second

	i := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		folder := w.folders[i%len(w.folders)]
		i++
		if err := w.idleFolder(ctx, c, folder, hasUpdate, idleWindow); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
}

func (w *connectionWorker) initFolder(c *imapClient.Client, folder string) error {
	if _, err := c.Select(folder, false); err != nil {
		return fmt.Errorf("SELECT %s: %v", folder, err)
	}
	if w.state.LastUID(folder) == 0 {
		if err := w.recordBaseUID(c, folder); err != nil {
			return err
		}
		log.Printf("[%s] %s: initialized (monitoring from now)", w.label(), folder)
	} else {
		if err := w.fetchNew(c, folder); err != nil {
			return err
		}
	}
	return nil
}

// idleFolder selects folder, enters IDLE for up to window, then returns.
// If an EXISTS update arrives during the window, new messages are fetched.
// rawConn.Close() called by the ctx-watcher goroutine in runLoop unblocks
// c.Idle() immediately, so the ctx.Done case here is always fast.
func (w *connectionWorker) idleFolder(ctx context.Context, c *imapClient.Client, folder string, hasUpdate <-chan struct{}, window time.Duration) error {
	if _, err := c.Select(folder, false); err != nil {
		return fmt.Errorf("SELECT %s: %v", folder, err)
	}

	// Drain any stale signal from the previous folder.
	select {
	case <-hasUpdate:
	default:
	}

	stop := make(chan struct{})
	idleErr := make(chan error, 1)
	go func() {
		idleErr <- c.Idle(stop, nil)
	}()

	timer := time.NewTimer(window)
	gotUpdate := false

	select {
	case <-hasUpdate:
		gotUpdate = true
	case <-timer.C:
	case err := <-idleErr:
		timer.Stop()
		return err
	case <-ctx.Done():
		// rawConn is already being closed by the goroutine in runLoop;
		// c.Idle() will return momentarily — just wait for it.
		timer.Stop()
		close(stop)
		<-idleErr
		return nil
	}

	timer.Stop()
	close(stop)
	if err := <-idleErr; err != nil && ctx.Err() == nil {
		return err
	}

	if gotUpdate && ctx.Err() == nil {
		// Drain any additional signals that arrived while we were stopping.
		select {
		case <-hasUpdate:
		default:
		}
		if err := w.fetchNew(c, folder); err != nil {
			return err
		}
	}
	return nil
}

func (w *connectionWorker) recordBaseUID(c *imapClient.Client, folder string) error {
	uids, err := c.UidSearch(&imap.SearchCriteria{})
	if err != nil {
		return fmt.Errorf("UID SEARCH ALL %s: %v", folder, err)
	}
	var max uint32
	for _, uid := range uids {
		if uid > max {
			max = uid
		}
	}
	return w.state.SetBaseUID(folder, max)
}

func (w *connectionWorker) fetchNew(c *imapClient.Client, folder string) error {
	lastUID := w.state.LastUID(folder)
	if lastUID == 0 {
		return nil
	}

	criteria := &imap.SearchCriteria{Uid: new(imap.SeqSet)}
	criteria.Uid.AddRange(lastUID+1, 0)

	uids, err := c.UidSearch(criteria)
	if err != nil {
		return fmt.Errorf("UID SEARCH %s: %v", folder, err)
	}
	if len(uids) == 0 {
		return nil
	}

	seqset := new(imap.SeqSet)
	for _, uid := range uids {
		seqset.AddNum(uid)
	}

	msgs := make(chan *imap.Message, len(uids))
	done := make(chan error, 1)
	go func() {
		done <- c.UidFetch(seqset, []imap.FetchItem{
			imap.FetchUid,
			imap.FetchEnvelope,
			imap.FetchRFC822,
			imap.FetchInternalDate,
		}, msgs)
	}()

	var batch []*imap.Message
	for msg := range msgs {
		batch = append(batch, msg)
	}
	if err := <-done; err != nil {
		return fmt.Errorf("UID FETCH %s: %v", folder, err)
	}

	for _, msg := range batch {
		if err := w.processMessage(msg, folder); err != nil {
			log.Printf("[%s] %s UID %d: %v", w.label(), folder, msg.Uid, err)
		}
	}
	return nil
}

func (w *connectionWorker) processMessage(msg *imap.Message, folder string) error {
	if msg == nil || msg.Envelope == nil {
		return nil
	}

	content := extractContent(msg)
	subject := msg.Envelope.Subject
	from := senderString(msg.Envelope.From)

	msgDate := msg.InternalDate
	if msgDate.IsZero() && !msg.Envelope.Date.IsZero() {
		msgDate = msg.Envelope.Date
	}
	if msgDate.IsZero() {
		msgDate = time.Now()
	}

	messageID := msg.Envelope.MessageId
	if messageID == "" {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d-%d", subject, msgDate.Unix(), msg.Uid)))
		messageID = fmt.Sprintf("<%x@wkmailsync.generated>", h[:8])
	}

	filename := buildFilename(msgDate, subject, from)
	safeFolder := sanitizeFolderName(folder)

	if msg.Uid <= w.state.LastUID(folder) {
		return nil
	}
	if w.state.IsKnownFile(safeFolder, filename) {
		_ = w.state.Record(folder, safeFolder, filename, msg.Uid)
		return nil
	}

	dir := filepath.Join(w.cfg.OutputDir, safeFolder)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir: %v", err)
	}
	filePath := filepath.Join(dir, filename)
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return fmt.Errorf("write EML: %v", err)
	}

	log.Printf("[%s] saved: %q from %s → %s", folder, subject, from, filename)

	if err := w.state.Record(folder, safeFolder, filename, msg.Uid); err != nil {
		log.Printf("[%s] state flush: %v", folder, err)
	}

	if w.newMsg != nil {
		w.newMsg(folder)
	}

	if w.webhook != nil {
		evt := WebhookEvent{
			MessageID: messageID,
			Subject:   subject,
			From:      from,
			Date:      msgDate,
			Folder:    folder,
			FilePath:  filePath,
			Body:      string(content),
		}
		go w.webhook.Send(evt)
	}

	return nil
}

// dial creates a raw net.Conn, wraps it with imapClient.New, and authenticates.
// Returning rawConn separately lets runLoop close it directly to unblock any
// in-flight IMAP operation without waiting for a server response.
func (w *connectionWorker) dial() (*imapClient.Client, net.Conn, error) {
	src := w.cfg.Source
	addr := net.JoinHostPort(src.Host, src.Port)

	var rawConn net.Conn
	var err error
	if src.UseTLS {
		tlsCfg := &tls.Config{ServerName: src.Host}
		if src.InsecureTLS {
			tlsCfg.InsecureSkipVerify = true
		}
		rawConn, err = tls.Dial("tcp", addr, tlsCfg)
	} else {
		rawConn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return nil, nil, err
	}

	c, err := imapClient.New(rawConn)
	if err != nil {
		rawConn.Close()
		return nil, nil, err
	}

	if w.tokens != nil {
		token, err := w.tokens.Token()
		if err != nil {
			rawConn.Close()
			return nil, nil, fmt.Errorf("OAuth2 token: %v", err)
		}
		if err := c.Authenticate(newXOAuth2Client(src.Username, token)); err != nil {
			rawConn.Close()
			return nil, nil, fmt.Errorf("OAuth2 auth: %v", err)
		}
	} else {
		if err := c.Login(src.Username, src.Password); err != nil {
			rawConn.Close()
			return nil, nil, err
		}
	}
	return c, rawConn, nil
}

func extractContent(msg *imap.Message) []byte {
	if msg.Body == nil {
		return nil
	}
	var r io.Reader
	for section, body := range msg.Body {
		if section != nil && section.Specifier == imap.EntireSpecifier {
			r = body
			break
		}
	}
	if r == nil {
		for _, body := range msg.Body {
			if body != nil {
				r = body
				break
			}
		}
	}
	if r == nil {
		return nil
	}
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.Bytes()
}

var filenameInvalid = regexp.MustCompile(`[<>:"/\\|?*\x00-\x1F]`)

func buildFilename(date time.Time, subject, from string) string {
	s := filenameInvalid.ReplaceAllString(subject, "_")
	s = strings.ReplaceAll(s, " ", "_")
	if len(s) > 60 {
		s = s[:60]
	}
	f := filenameInvalid.ReplaceAllString(from, "_")
	f = strings.ReplaceAll(f, " ", "_")
	if len(f) > 40 {
		f = f[:40]
	}
	return fmt.Sprintf("%s_%s_%s.eml", date.UTC().Format("20060102_150405"), s, f)
}

func senderString(addrs []*imap.Address) string {
	if len(addrs) == 0 {
		return ""
	}
	a := addrs[0]
	if a.PersonalName != "" {
		return a.PersonalName
	}
	if a.MailboxName != "" && a.HostName != "" {
		return a.MailboxName + "@" + a.HostName
	}
	return a.MailboxName
}
