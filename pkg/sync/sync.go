package sync

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
	"github.com/Warky-Devs/WkMailSync/pkg/output"
	"github.com/Warky-Devs/WkMailSync/pkg/source"
)

type SyncEngine struct {
	Source   source.MailSource
	Output   output.MailOutput
	DateFrom time.Time
	DateTo   time.Time
	DryRun   bool
	Stats    *config.SyncStats
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

	for i, folder := range folders {
		log.Printf("[%d/%d] Processing folder: %s", i+1, len(folders), folder.Name)
		if err := e.syncFolder(folder); err != nil {
			log.Printf("Failed to sync folder %s: %v", folder.Name, err)
			e.Stats.Errors++
		}
	}

	return nil
}

func (e *SyncEngine) syncFolder(folder source.Folder) error {
	messages, err := e.Source.ListMessages(folder)
	if err != nil {
		return fmt.Errorf("failed to list messages: %v", err)
	}

	e.Stats.TotalMessages += len(messages)
	log.Printf("  Found %d messages", len(messages))

	copied := 0
	skipped := 0

	for _, msg := range messages {
		if !e.shouldProcess(msg) {
			skipped++
			e.Stats.SkippedMessages++
			continue
		}

		filename := e.buildFilename(msg)

		if e.Output.Exists(filename) {
			skipped++
			e.Stats.SkippedMessages++
			continue
		}

		if e.DryRun {
			log.Printf("  Would write: %s/%s", folder.Name, filename)
			copied++
			e.Stats.CopiedMessages++
			continue
		}

		if err := e.Output.WriteMessage(folder.Name, filename, msg.Content); err != nil {
			log.Printf("  Failed to write message %s: %v", filename, err)
			e.Stats.Errors++
			continue
		}

		copied++
		e.Stats.CopiedMessages++
	}

	log.Printf("  Copied: %d, Skipped: %d", copied, skipped)
	return nil
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
	log.Printf("Total messages: %d", e.Stats.TotalMessages)
	log.Printf("Copied messages: %d", e.Stats.CopiedMessages)
	log.Printf("Skipped messages: %d", e.Stats.SkippedMessages)
	if e.Stats.Errors > 0 {
		log.Printf("Errors: %d", e.Stats.Errors)
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
