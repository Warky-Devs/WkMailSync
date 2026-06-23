package monitor

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
	"github.com/emersion/go-imap"
	imapClient "github.com/emersion/go-imap/client"
)

type MonitorEngine struct {
	cfg     *config.MonitorConfig
	state   *StateStore
	webhook *WebhookClient
	tokens  *TokenSource
	counts  map[string]*atomic.Int64 // populated before goroutines start; map is read-only after
	startAt time.Time
}

func New(cfg *config.MonitorConfig) *MonitorEngine {
	e := &MonitorEngine{
		cfg:     cfg,
		counts:  make(map[string]*atomic.Int64),
		startAt: time.Now(),
	}

	stateFile := cfg.StateFile
	if stateFile == "" {
		stateFile = filepath.Join(cfg.OutputDir, ".wkmonitor_state.json")
	}
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		log.Printf("warning: cannot create output dir %s: %v", cfg.OutputDir, err)
	}
	e.state = NewStateStore(stateFile, cfg.OutputDir)

	if cfg.Webhook != nil && cfg.Webhook.Enabled && cfg.Webhook.URL != "" {
		e.webhook = NewWebhookClient(*cfg.Webhook)
	}

	if cfg.Source.OAuth2 != nil {
		e.tokens = NewTokenSource(*cfg.Source.OAuth2)
	}

	return e
}

// Run blocks until ctx is cancelled. It discovers folders, distributes them
// across at most max_connections IMAP connections, and logs status every 15 min.
func (e *MonitorEngine) Run(ctx context.Context) error {
	if err := e.state.Load(); err != nil {
		return fmt.Errorf("load state: %v", err)
	}

	folders, err := e.discoverFolders()
	if err != nil {
		return fmt.Errorf("discover folders: %v", err)
	}
	if len(folders) == 0 {
		return fmt.Errorf("no folders to monitor after applying include/exclude filters")
	}

	groups := divideFolders(folders, e.cfg.MaxConnections)
	log.Printf("monitoring %d folder(s) across %d connection(s) on %s (idle window: %ds)",
		len(folders), len(groups), e.cfg.Source.Host, e.cfg.IdleWindowSec)

	// Populate the counters map before any goroutine starts so workers can
	// increment atomically without touching the map structure.
	for _, f := range folders {
		var c atomic.Int64
		e.counts[f] = &c
	}

	var wg sync.WaitGroup
	for i, group := range groups {
		id := i + 1
		g := group
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := &connectionWorker{
				id:      id,
				folders: g,
				cfg:     *e.cfg,
				state:   e.state,
				webhook: e.webhook,
				tokens:  e.tokens,
				newMsg: func(fld string) {
					if c, ok := e.counts[fld]; ok {
						c.Add(1)
					}
				},
			}
			w.run(ctx)
		}()
	}

	go e.statusTicker(ctx)

	wg.Wait()
	log.Printf("monitor stopped — state flushed")
	return nil
}

func (e *MonitorEngine) statusTicker(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			uptime := time.Since(e.startAt).Round(time.Second)
			parts := make([]string, 0, len(e.counts))
			for folder, c := range e.counts {
				parts = append(parts, fmt.Sprintf("%s(%d new)", folder, c.Load()))
			}
			log.Printf("still monitoring: %s — uptime %s", strings.Join(parts, " "), uptime)
		case <-ctx.Done():
			return
		}
	}
}

func (e *MonitorEngine) discoverFolders() ([]string, error) {
	tmp := &connectionWorker{cfg: *e.cfg, tokens: e.tokens}
	c, rawConn, err := tmp.dial()
	if err != nil {
		return nil, fmt.Errorf("connect: %v", err)
	}
	defer rawConn.Close()
	return listFolders(c, e.cfg.FolderInclude, e.cfg.FolderExclude)
}

func listFolders(c *imapClient.Client, include, exclude []string) ([]string, error) {
	mailboxes := make(chan *imap.MailboxInfo, 16)
	done := make(chan error, 1)
	go func() {
		done <- c.List("", "*", mailboxes)
	}()

	var all []string
	for m := range mailboxes {
		if !hasAttribute(m.Attributes, imap.NoSelectAttr) {
			all = append(all, m.Name)
		}
	}
	if err := <-done; err != nil {
		return nil, fmt.Errorf("LIST: %v", err)
	}

	var filtered []string
	for _, name := range all {
		if !skipFolder(name, include, exclude) {
			filtered = append(filtered, name)
		}
	}
	return filtered, nil
}

// divideFolders distributes folders as evenly as possible across n groups.
// If n > len(folders), it uses len(folders) groups (one per folder).
func divideFolders(folders []string, n int) [][]string {
	if n <= 0 {
		n = 1
	}
	if n > len(folders) {
		n = len(folders)
	}
	groups := make([][]string, n)
	for i, f := range folders {
		groups[i%n] = append(groups[i%n], f)
	}
	return groups
}

func hasAttribute(attrs []string, target string) bool {
	for _, a := range attrs {
		if strings.EqualFold(a, target) {
			return true
		}
	}
	return false
}

func skipFolder(name string, include, exclude []string) bool {
	if len(include) > 0 {
		for _, f := range include {
			if strings.EqualFold(f, name) {
				return false
			}
		}
		return true
	}
	for _, f := range exclude {
		if strings.EqualFold(f, name) {
			return true
		}
	}
	return false
}
