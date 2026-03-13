package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
	"github.com/Warky-Devs/WkMailSync/pkg/connector"
	"github.com/Warky-Devs/WkMailSync/pkg/output"
	"github.com/Warky-Devs/WkMailSync/pkg/source"
	syncp "github.com/Warky-Devs/WkMailSync/pkg/sync"
)

func main() {
	var (
		configFile  = flag.String("config", "", "YAML config file path")
		srcHost     = flag.String("src-host", "", "Source IMAP host")
		srcPort     = flag.String("src-port", "993", "Source IMAP port")
		srcUser     = flag.String("src-user", "", "Source username")
		srcPass     = flag.String("src-pass", "", "Source password")
		srcTLS      = flag.Bool("src-tls", true, "Use TLS for source")
		srcInsecure = flag.Bool("src-insecure", false, "Skip certificate verification for source")

		destHost     = flag.String("dest-host", "", "Destination IMAP host")
		destPort     = flag.String("dest-port", "993", "Destination IMAP port")
		destUser     = flag.String("dest-user", "", "Destination username")
		destPass     = flag.String("dest-pass", "", "Destination password")
		destTLS      = flag.Bool("dest-tls", true, "Use TLS for destination")
		destInsecure = flag.Bool("dest-insecure", false, "Skip certificate verification for destination")

		dryRun       = flag.Bool("dry-run", false, "Show what would be synced without doing it")
		outputDir    = flag.String("output-dir", "", "Output directory for EML files")
		subdirectory = flag.String("subdirectory", "", "Optional subdirectory in destination")
		dateFrom     = flag.String("date-from", "", "Only sync messages from this date (YYYY-MM-DD)")
		dateTo       = flag.String("date-to", "", "Only sync messages up to this date (YYYY-MM-DD)")
		outputFormat = flag.String("output-format", "eml", "Output format: eml or zip")
	)
	flag.Parse()

	var cfg *config.Config
	var err error

	if *configFile != "" {
		cfg, err = config.LoadConfig(*configFile)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
	} else {
		if *srcHost == "" || *srcUser == "" || *srcPass == "" {
			log.Fatal("Source server credentials required (use -config or flags)")
		}
		cfg = &config.Config{
			Source: config.ServerConfig{
				Host:        *srcHost,
				Port:        *srcPort,
				Username:    *srcUser,
				Password:    *srcPass,
				UseTLS:      *srcTLS,
				InsecureTLS: *srcInsecure,
			},
			Dest: config.ServerConfig{
				Host:        *destHost,
				Port:        *destPort,
				Username:    *destUser,
				Password:    *destPass,
				UseTLS:      *destTLS,
				InsecureTLS: *destInsecure,
			},
			OutputDir:    *outputDir,
			DryRun:       *dryRun,
			Subdirectory: *subdirectory,
			DateFrom:     *dateFrom,
			DateTo:       *dateTo,
			OutputFormat: *outputFormat,
		}
	}

	var dateFromParsed, dateToParsed time.Time
	if cfg.DateFrom != "" {
		dateFromParsed, err = config.ParseDateString(cfg.DateFrom)
		if err != nil {
			log.Fatalf("Invalid date-from: %v", err)
		}
	}
	if cfg.DateTo != "" {
		dateToParsed, err = config.ParseDateString(cfg.DateTo)
		if err != nil {
			log.Fatalf("Invalid date-to: %v", err)
		}
	}
	if !dateFromParsed.IsZero() && !dateToParsed.IsZero() && dateFromParsed.After(dateToParsed) {
		log.Fatalf("date-from cannot be after date-to")
	}

	if cfg.Virtualmin != nil {
		runVirtualmin(cfg, dateFromParsed, dateToParsed)
		return
	}

	if cfg.MaildirSource != nil {
		runMaildirSync(cfg, dateFromParsed, dateToParsed)
		return
	}

	runIMAPSync(cfg, dateFromParsed, dateToParsed)
}

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

	if err := engine.Run(); err != nil {
		log.Fatalf("Sync failed: %v", err)
	}
	engine.PrintStats()
}

func runMaildirSync(cfg *config.Config, dateFrom, dateTo time.Time) {
	md := cfg.MaildirSource
	src, err := source.NewMaildirSource(md.Path)
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

	if err := engine.Run(); err != nil {
		log.Fatalf("Sync failed: %v", err)
	}
	engine.PrintStats()
}

func runVirtualmin(cfg *config.Config, dateFrom, dateTo time.Time) {
	vm := cfg.Virtualmin
	var conn connector.VirtualminConnector
	var err error

	switch vm.Mode {
	case "local":
		conn = connector.NewLocalConnector(vm)
	case "ssh":
		sshConn, sshErr := connector.NewSSHConnector(vm)
		if sshErr != nil {
			log.Fatalf("SSH connector failed: %v", sshErr)
		}
		defer sshConn.Close()

		domains, err := sshConn.ListDomains()
		if err != nil {
			log.Fatalf("Failed to list domains: %v", err)
		}
		for _, domain := range domains {
			users, err := sshConn.ListUsers(domain)
			if err != nil {
				log.Printf("Failed to list users for %s: %v", domain, err)
				continue
			}
			for _, user := range users {
				src := sshConn.NewMaildirSource(user.MaildirPath)
				username := user.Username + "@" + user.Domain
				out, err := buildOutput(cfg, username)
				if err != nil {
					log.Printf("Failed to create output for %s: %v", username, err)
					continue
				}
				runEngineForUser(src, out, cfg, dateFrom, dateTo, username)
			}
		}
		return

	case "api":
		conn, err = connector.NewAPIConnector(vm)
		if err != nil {
			log.Fatalf("API connector failed: %v", err)
		}
	default:
		log.Fatalf("Unknown virtualmin mode: %s (use local, ssh, or api)", vm.Mode)
	}

	if conn != nil {
		defer conn.Close()
	}

	domains, err := conn.ListDomains()
	if err != nil {
		log.Fatalf("Failed to list domains: %v", err)
	}

	for _, domain := range domains {
		users, err := conn.ListUsers(domain)
		if err != nil {
			log.Printf("Failed to list users for %s: %v", domain, err)
			continue
		}
		for _, user := range users {
			src, err := source.NewMaildirSource(user.MaildirPath)
			if err != nil {
				log.Printf("Failed to open maildir for %s@%s: %v", user.Username, user.Domain, err)
				continue
			}
			username := user.Username + "@" + user.Domain
			out, err := buildOutput(cfg, username)
			if err != nil {
				log.Printf("Failed to create output for %s: %v", username, err)
				src.Close()
				continue
			}
			runEngineForUser(src, out, cfg, dateFrom, dateTo, username)
		}
	}
}

func runEngineForUser(src source.MailSource, out output.MailOutput, cfg *config.Config, dateFrom, dateTo time.Time, username string) {
	defer src.Close()
	defer out.Close()

	engine := syncp.NewSyncEngine(src, out)
	engine.DateFrom = dateFrom
	engine.DateTo = dateTo
	engine.DryRun = cfg.DryRun

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
