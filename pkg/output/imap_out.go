package output

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
	imapClient "github.com/emersion/go-imap/client"
)

type IMAPOutput struct {
	client   *imapClient.Client
	cfg      config.ServerConfig
	existing map[string]bool
}

func ConnectIMAP(cfg config.ServerConfig) (*imapClient.Client, error) {
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

func NewIMAPOutput(cfg config.ServerConfig) (*IMAPOutput, error) {
	c, err := ConnectIMAP(cfg)
	if err != nil {
		return nil, err
	}
	return &IMAPOutput{
		client:   c,
		cfg:      cfg,
		existing: make(map[string]bool),
	}, nil
}

func (o *IMAPOutput) Client() *imapClient.Client {
	return o.client
}

func (o *IMAPOutput) LoadExistingFolder(folder string) error {
	mbox, err := o.client.Select(folder, false)
	if err != nil {
		return nil
	}
	_ = mbox
	return nil
}

func (o *IMAPOutput) Reconnect() error {
	if o.client != nil {
		o.client.Logout()
	}
	c, err := ConnectIMAP(o.cfg)
	if err != nil {
		return fmt.Errorf("failed to reconnect to IMAP destination: %v", err)
	}
	o.client = c
	return nil
}

func (o *IMAPOutput) EnsureConnected() error {
	if o.client == nil {
		return o.Reconnect()
	}
	if err := o.client.Noop(); err != nil {
		log.Printf("Destination connection lost, reconnecting: %v", err)
		return o.Reconnect()
	}
	return nil
}

func (o *IMAPOutput) WriteMessage(folder, filename string, content []byte) error {
	return o.writeWithRetry(folder, filename, content, nil, time.Now(), 3)
}

func (o *IMAPOutput) WriteMessageWithMeta(folder, filename string, content []byte, flags []string, date time.Time) error {
	return o.writeWithRetry(folder, filename, content, flags, date, 3)
}

func (o *IMAPOutput) writeWithRetry(folder, _ string, content []byte, flags []string, date time.Time, maxRetries int) error {
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			if err := o.EnsureConnected(); err != nil {
				continue
			}
		}
		err := o.client.Append(folder, flags, date, bytes.NewReader(content))
		if err == nil {
			return nil
		}
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "not logged in") ||
			strings.Contains(errStr, "connection") ||
			strings.Contains(errStr, "timeout") {
			if attempt < maxRetries {
				time.Sleep(time.Duration(attempt) * time.Second)
				continue
			}
		}
		return err
	}
	return fmt.Errorf("failed after %d attempts", maxRetries)
}

func (o *IMAPOutput) Exists(key string) bool {
	return o.existing[key]
}

func (o *IMAPOutput) MarkExists(key string) {
	o.existing[key] = true
}

func (o *IMAPOutput) Close() error {
	if o.client != nil {
		return o.client.Logout()
	}
	return nil
}
