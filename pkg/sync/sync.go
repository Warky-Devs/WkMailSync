package sync

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
	"github.com/Warky-Devs/WkMailSync/pkg/output"
	"github.com/Warky-Devs/WkMailSync/pkg/source"
)

type syncState struct {
	path string
	uids map[string]uint32 // folder name → last copied UID
}

func (s *syncState) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return // missing state file is fine on first run
	}
	_ = json.Unmarshal(data, &s.uids)
}

func (s *syncState) lastUID(folder string) uint32 {
	return s.uids[folder]
}

func (s *syncState) update(folder string, uid uint32) {
	if uid > s.uids[folder] {
		s.uids[folder] = uid
	}
}

func (s *syncState) flush() {
	data, err := json.MarshalIndent(s.uids, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(s.path), 0755)
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return
	}
	_ = os.Rename(tmp, s.path)
}

type SyncEngine struct {
	Source        source.MailSource
	Output        output.MailOutput
	DateFrom      time.Time
	DateTo        time.Time
	DryRun        bool
	Stats         *config.SyncStats
	FolderInclude []string // only sync these folders; empty = all
	FolderExclude []string // skip these folders
	StateFile     string   // path to state JSON; empty disables state tracking
}

func NewSyncEngine(src source.MailSource, out output.MailOutput) *SyncEngine {
	return &SyncEngine{
		Source: src,
		Output: out,
		Stats:  &config.SyncStats{},
	}
}

func (e *SyncEngine) Run() error {
	folders, err := e.Source.ListFolders()
	if err != nil {
		return fmt.Errorf("failed to list folders: %v", err)
	}

	e.Stats.TotalMailboxes = len(folders)
	log.Printf("Found %d folders to sync", len(folders))

	state := &syncState{path: e.StateFile, uids: make(map[string]uint32)}
	if e.StateFile != "" {
		state.load()
	}

	for i, folder := range folders {
		if skip, reason := e.skipFolder(folder.Name); skip {
			log.Printf("[%d/%d] Skipping folder %s (%s)", i+1, len(folders), folder.Name, reason)
			continue
		}
		afterUID := state.lastUID(folder.Name)
		if afterUID > 0 {
			log.Printf("[%d/%d] Processing folder: %s (resuming after UID %d)", i+1, len(folders), folder.Name, afterUID)
		} else {
			log.Printf("[%d/%d] Processing folder: %s", i+1, len(folders), folder.Name)
		}
		if err := e.syncFolder(folder, i+1, len(folders), state); err != nil {
			log.Printf("Failed to sync folder %s: %v", folder.Name, err)
			e.Stats.Errors++
		}
		if e.StateFile != "" {
			state.flush()
		}
	}

	return nil
}

func (e *SyncEngine) syncFolder(folder source.Folder, idx, total int, state *syncState) error {
	var copied, skipped, processed, bytesCopied atomic.Int64

	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				log.Printf("[%d/%d] %s: %d processed (%d copied %s, %d skipped)",
					idx, total, folder.Name,
					processed.Load(), copied.Load(), formatSize(bytesCopied.Load()), skipped.Load())
			case <-stop:
				return
			}
		}
	}()

	for msg, err := range e.Source.Messages(folder, state.lastUID(folder.Name)) {
		if err != nil {
			log.Printf("  Error reading message: %v", err)
			e.Stats.Errors++
			continue
		}

		msgSize := int64(len(msg.Content))
		processed.Add(1)
		e.Stats.TotalMessages++
		e.Stats.BytesTotal += msgSize

		if !e.shouldProcess(msg) {
			skipped.Add(1)
			e.Stats.SkippedMessages++
			continue
		}

		filename := e.buildFilename(msg)

		if e.Output.Exists(filename) {
			skipped.Add(1)
			e.Stats.SkippedMessages++
			continue
		}

		if e.DryRun {
			log.Printf("  Would write: %s/%s", folder.Name, filename)
			copied.Add(1)
			bytesCopied.Add(msgSize)
			e.Stats.CopiedMessages++
			e.Stats.BytesCopied += msgSize
			state.update(folder.Name, msg.UID)
			continue
		}

		if err := e.Output.WriteMessage(folder.Name, filename, msg.Content); err != nil {
			log.Printf("  Failed to write message %s: %v", filename, err)
			e.Stats.Errors++
			continue
		}

		copied.Add(1)
		bytesCopied.Add(msgSize)
		e.Stats.CopiedMessages++
		e.Stats.BytesCopied += msgSize
		state.update(folder.Name, msg.UID)
	}

	close(stop)
	log.Printf("[%d/%d] %s done: %d copied (%s), %d skipped",
		idx, total, folder.Name, copied.Load(), formatSize(bytesCopied.Load()), skipped.Load())
	return nil
}

func formatSize(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func (e *SyncEngine) skipFolder(name string) (bool, string) {
	if len(e.FolderInclude) > 0 {
		for _, f := range e.FolderInclude {
			if strings.EqualFold(f, name) {
				return false, ""
			}
		}
		return true, "not in folder_include"
	}
	for _, f := range e.FolderExclude {
		if strings.EqualFold(f, name) {
			return true, "in folder_exclude"
		}
	}
	return false, ""
}

func (e *SyncEngine) shouldProcess(msg source.Message) bool {
	if e.DateFrom.IsZero() && e.DateTo.IsZero() {
		return true
	}
	if msg.Date.IsZero() {
		return false
	}
	if !e.DateFrom.IsZero() && msg.Date.Before(e.DateFrom) {
		return false
	}
	if !e.DateTo.IsZero() && msg.Date.After(e.DateTo) {
		return false
	}
	return true
}

func (e *SyncEngine) buildFilename(msg source.Message) string {
	date := msg.Date
	if date.IsZero() {
		date = time.Now()
	}
	subject := sanitizeFilename(msg.Subject)
	from := sanitizeFilename(msg.From)
	return fmt.Sprintf("%s_%s_%s.eml",
		date.Format("20060102_150405"),
		subject,
		from)
}

func (e *SyncEngine) PrintStats() {
	log.Printf("\n=== Sync Complete ===")
	log.Printf("Total mailboxes: %d", e.Stats.TotalMailboxes)
	log.Printf("Total messages:  %d (%s)", e.Stats.TotalMessages, formatSize(e.Stats.BytesTotal))
	log.Printf("Copied:          %d (%s)", e.Stats.CopiedMessages, formatSize(e.Stats.BytesCopied))
	log.Printf("Skipped:         %d", e.Stats.SkippedMessages)
	if e.Stats.Errors > 0 {
		log.Printf("Errors:          %d", e.Stats.Errors)
	}
}

func sanitizeFilename(input string) string {
	invalidChars := regexp.MustCompile(`[<>:"/\\|?*\x00-\x1F]`)
	sanitized := invalidChars.ReplaceAllString(input, "_")
	sanitized = strings.ReplaceAll(sanitized, " ", "_")
	if len(sanitized) > 100 {
		sanitized = sanitized[:100]
	}
	return sanitized
}
