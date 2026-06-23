package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
)

type WebhookEvent struct {
	MessageID string    `json:"message_id"`
	Subject   string    `json:"subject"`
	From      string    `json:"from"`
	Date      time.Time `json:"date"`
	Folder    string    `json:"folder"`
	FilePath  string    `json:"file_path"`
	Body      string    `json:"body,omitempty"`
}

type WebhookClient struct {
	cfg    config.WebhookConfig
	client *http.Client
}

func NewWebhookClient(cfg config.WebhookConfig) *WebhookClient {
	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &WebhookClient{
		cfg:    cfg,
		client: &http.Client{Timeout: timeout},
	}
}

// Send posts the event to the configured webhook URL.
// It retries up to 3 times with exponential backoff, then logs and returns.
func (w *WebhookClient) Send(evt WebhookEvent) {
	if w.cfg.URL == "" {
		return
	}

	// IncludeBody nil means default true; explicit false strips the body.
	if w.cfg.IncludeBody != nil && !*w.cfg.IncludeBody {
		evt.Body = ""
	}

	data, err := json.Marshal(evt)
	if err != nil {
		log.Printf("[webhook] marshal error: %v", err)
		return
	}

	backoff := time.Second
	for attempt := 1; attempt <= 3; attempt++ {
		if err = w.post(data); err == nil {
			return
		}
		if attempt < 3 {
			time.Sleep(backoff)
			backoff *= 2
		}
	}
	log.Printf("[webhook] failed after 3 retries: %v — continuing", err)
}

func (w *WebhookClient) post(data []byte) error {
	resp, err := w.client.Post(w.cfg.URL, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("non-2xx status %d", resp.StatusCode)
	}
	return nil
}
