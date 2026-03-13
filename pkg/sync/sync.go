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
	Source        source.MailSource
	Output        output.MailOutput
	DateFrom      time.Time
	DateTo        time.Time
	DryRun        bool
	Stats         *config.SyncStats
	FolderInclude []string // only sync these folders; empty = all
	FolderExclude []string // skip these folders
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
		if skip, reason := e.skipFolder(folder.Name); skip {
			log.Printf("[%d/%d] Skipping folder %s (%s)", i+1, len(folders), folder.Name, reason)
			continue
		}
		log.Printf("[%d/%d] Processing folder: %s", i+1, len(folders), folder.Name)
		if err := e.syncFolder(folder); err != nil {
			log.Printf("Failed to sync folder %s: %v", folder.Name, err)
			e.Stats.Errors++
		}
	}

	return nil
}

func (e *SyncEngine) syncFolder(folder source.Folder) error {
	copied := 0
	skipped := 0

	for msg, err := range e.Source.Messages(folder) {
		if err != nil {
			log.Printf("  Error reading message: %v", err)
			e.Stats.Errors++
			continue
		}

		e.Stats.TotalMessages++

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
