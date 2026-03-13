package main

import (
	"fmt"
	"log"
	"time"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
	"github.com/Warky-Devs/WkMailSync/pkg/output"
	"github.com/Warky-Devs/WkMailSync/pkg/source"
	syncp "github.com/Warky-Devs/WkMailSync/pkg/sync"
)

func runIMAPSync(cfg *config.Config, dateFrom, dateTo time.Time) {
	src, err := source.NewIMAPSource(cfg.Source)
	if err != nil {
		log.Fatalf("Failed to connect to source: %v", err)
	}
	defer src.Close()

	out, err := buildOutput(cfg, "")
	if err != nil {
		log.Fatalf("Failed to create output: %v", err)
	}
	defer out.Close()

	engine := syncp.NewSyncEngine(src, out)
	engine.DateFrom = dateFrom
	engine.DateTo = dateTo
	engine.DryRun = cfg.DryRun
	engine.FolderInclude = cfg.FolderInclude
	engine.FolderExclude = cfg.FolderExclude

	if err := engine.Run(); err != nil {
		log.Fatalf("Sync failed: %v", err)
	}
	engine.PrintStats()
}

func runMaildirSync(cfg *config.Config, dateFrom, dateTo time.Time) {
	src, err := source.NewMaildirSource(cfg.MaildirSource.Path)
	if err != nil {
		log.Fatalf("Failed to open maildir: %v", err)
	}
	defer src.Close()

	out, err := buildOutput(cfg, "")
	if err != nil {
		log.Fatalf("Failed to create output: %v", err)
	}
	defer out.Close()

	engine := syncp.NewSyncEngine(src, out)
	engine.DateFrom = dateFrom
	engine.DateTo = dateTo
	engine.DryRun = cfg.DryRun
	engine.FolderInclude = cfg.FolderInclude
	engine.FolderExclude = cfg.FolderExclude

	if err := engine.Run(); err != nil {
		log.Fatalf("Sync failed: %v", err)
	}
	engine.PrintStats()
}

func runEngineForUser(src source.MailSource, out output.MailOutput, cfg *config.Config, dateFrom, dateTo time.Time, username string) {
	defer src.Close()
	defer out.Close()

	engine := syncp.NewSyncEngine(src, out)
	engine.DateFrom = dateFrom
	engine.DateTo = dateTo
	engine.DryRun = cfg.DryRun
	engine.FolderInclude = cfg.FolderInclude
	engine.FolderExclude = cfg.FolderExclude

	log.Printf("Syncing user: %s", username)
	if err := engine.Run(); err != nil {
		log.Printf("Sync failed for %s: %v", username, err)
		return
	}
	engine.PrintStats()
}

func buildOutput(cfg *config.Config, username string) (output.MailOutput, error) {
	format := cfg.OutputFormat
	if format == "" {
		format = "eml"
	}

	switch format {
	case "zip":
		return output.NewZipOutput(cfg.OutputDir, username)
	case "eml":
		if cfg.OutputDir != "" {
			return output.NewEMLOutput(cfg.OutputDir, username)
		}
		return output.NewIMAPOutput(cfg.Dest)
	default:
		return nil, fmt.Errorf("unknown output format: %s", format)
	}
}
