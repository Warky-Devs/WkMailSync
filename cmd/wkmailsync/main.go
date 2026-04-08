package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
)

var version = "1.0.10"

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

		dryRun         = flag.Bool("dry-run", false, "Show what would be synced without doing it")
		outputDir      = flag.String("output-dir", "", "Output directory for EML files")
		subdirectory   = flag.String("subdirectory", "", "Optional subdirectory in destination")
		dateFrom       = flag.String("date-from", "", "Only sync messages from this date (YYYY-MM-DD)")
		dateTo         = flag.String("date-to", "", "Only sync messages up to this date (YYYY-MM-DD)")
		outputFormat   = flag.String("output-format", "eml", "Output format: eml or zip")
		generateConfig = flag.String("generate-config", "", "Write example config.example.yaml and exit (imap, maildir, virtualmin)")
		showVersion    = flag.Bool("v", false, "Print version and exit")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "wkmailsync %s - IMAP/Maildir mail sync and backup tool\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  wkmailsync -config config.yaml\n")
		fmt.Fprintf(os.Stderr, "  wkmailsync -src-host mail.example.com -src-user user -src-pass pass [flags]\n")
		fmt.Fprintf(os.Stderr, "  wkmailsync -generate-config [imap|maildir|virtualmin]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("wkmailsync %s\n", version)
		os.Exit(0)
	}

	if *generateConfig != "" {
		generateExampleConfig(*generateConfig)
		os.Exit(0)
	}

	var cfg *config.Config
	var err error

	if *configFile != "" {
		cfg, err = config.LoadConfig(*configFile)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
	} else {
		if *srcHost == "" || *srcUser == "" || *srcPass == "" {
			fmt.Fprintf(os.Stderr, "Error: source server credentials required\n\n")
			flag.Usage()
			os.Exit(1)
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
		log.Printf("Mode: Virtualmin (%s)", cfg.Virtualmin.Mode)
		log.Printf("Output: %s -> %s", cfg.OutputFormat, cfg.OutputDir)
		if !dateFromParsed.IsZero() {
			log.Printf("Date filter from: %s", dateFromParsed.Format("2006-01-02"))
		}
		if !dateToParsed.IsZero() {
			log.Printf("Date filter to:   %s", dateToParsed.Format("2006-01-02"))
		}
		runVirtualmin(cfg, dateFromParsed, dateToParsed)
		return
	}

	if cfg.MaildirSource != nil {
		log.Printf("Mode: Maildir source -> %s (%s)", cfg.OutputDir, cfg.OutputFormat)
		log.Printf("Maildir path: %s", cfg.MaildirSource.Path)
		runMaildirSync(cfg, dateFromParsed, dateToParsed)
		return
	}

	runIMAPSync(cfg, dateFromParsed, dateToParsed)
}
