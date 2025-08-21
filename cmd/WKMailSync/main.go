package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/charset"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/encoding/charmap"
	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Host        string `yaml:"host"`
	Port        string `yaml:"port"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	UseTLS      bool   `yaml:"use_tls"`
	InsecureTLS bool   `yaml:"insecure_tls"`
}

type Config struct {
	Source    ServerConfig `yaml:"source"`
	Dest      ServerConfig `yaml:"destination"`
	OutputDir string       `yaml:"output_dir"`
	DryRun    bool         `yaml:"dry_run"`
}

type SyncStats struct {
	TotalMailboxes  int
	TotalMessages   int
	CopiedMessages  int
	SkippedMessages int
	Errors          int
}

type SyncTool struct {
	source     *client.Client
	dest       *client.Client
	outputDir  string
	stats      *SyncStats
	srcConfig  ServerConfig
	destConfig ServerConfig
}

func init() {
	// Register additional charsets
	asciiEncoding := unicode.UTF8 // ASCII is compatible with UTF-8
	charset.RegisterEncoding("ascii", asciiEncoding)
	charset.RegisterEncoding("us-ascii", asciiEncoding)
	charset.RegisterEncoding("ASCII", asciiEncoding)
	charset.RegisterEncoding("US-ASCII", asciiEncoding)
	
	// Register Windows charsets
	charset.RegisterEncoding("windows-1252", charmap.Windows1252)
	charset.RegisterEncoding("WINDOWS-1252", charmap.Windows1252)
	charset.RegisterEncoding("cp1252", charmap.Windows1252)
	charset.RegisterEncoding("CP1252", charmap.Windows1252)
	
	// Register other common charsets
	charset.RegisterEncoding("iso-8859-1", charmap.ISO8859_1)
	charset.RegisterEncoding("ISO-8859-1", charmap.ISO8859_1)
	charset.RegisterEncoding("latin1", charmap.ISO8859_1)
	charset.RegisterEncoding("LATIN1", charmap.ISO8859_1)
}

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

		dryRun    = flag.Bool("dry-run", false, "Show what would be synced without actually doing it")
		outputDir = flag.String("output-dir", "", "Output directory for EML files (alternative to IMAP destination)")
	)
	flag.Parse()

	var srcConfig, destConfig ServerConfig
	var dryRunFlag bool
	var outputDirFlag string

	// Load from config file if provided
	if *configFile != "" {
		config, err := loadConfig(*configFile)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
		srcConfig = config.Source
		destConfig = config.Dest
		dryRunFlag = config.DryRun
		outputDirFlag = config.OutputDir
	} else {
		// Use command line flags
		if *srcHost == "" || *srcUser == "" || *srcPass == "" {
			log.Fatal("Source server credentials are required (use -config or individual flags)")
		}
		if *outputDir == "" && (*destHost == "" || *destUser == "" || *destPass == "") {
			log.Fatal("Either output directory or destination server credentials are required")
		}
		srcConfig = ServerConfig{*srcHost, *srcPort, *srcUser, *srcPass, *srcTLS, *srcInsecure}
		destConfig = ServerConfig{*destHost, *destPort, *destUser, *destPass, *destTLS, *destInsecure}
		dryRunFlag = *dryRun
		outputDirFlag = *outputDir
	}

	syncer := &SyncTool{
		outputDir:  outputDirFlag,
		stats:      &SyncStats{},
		srcConfig:  srcConfig,
		destConfig: destConfig,
	}

	// Connect to source server
	var err error
	syncer.source, err = connect(srcConfig)
	if err != nil {
		log.Fatalf("Failed to connect to source: %v", err)
	}
	defer syncer.source.Logout()

	// Connect to destination server only if not using file output
	if outputDirFlag == "" {
		syncer.dest, err = connect(destConfig)
		if err != nil {
			log.Fatalf("Failed to connect to destination: %v", err)
		}
		defer syncer.dest.Logout()
	}

	// Sync all mailboxes
	if err := syncer.syncAll(dryRunFlag); err != nil {
		log.Fatalf("Sync failed: %v", err)
	}

	// Print final stats
	syncer.printFinalStats()
}

func connect(config ServerConfig) (*client.Client, error) {
	addr := fmt.Sprintf("%s:%s", config.Host, config.Port)

	var c *client.Client
	var err error

	if config.UseTLS {
		tlsConfig := &tls.Config{ServerName: config.Host}
		if config.InsecureTLS {
			tlsConfig.InsecureSkipVerify = true
		}
		c, err = client.DialTLS(addr, tlsConfig)
	} else {
		c, err = client.Dial(addr)
	}

	if err != nil {
		return nil, err
	}

	if err := c.Login(config.Username, config.Password); err != nil {
		c.Logout()
		return nil, err
	}

	return c, nil
}

func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	// Set defaults
	if config.Source.Port == "" {
		config.Source.Port = "993"
	}
	if config.Dest.Port == "" {
		config.Dest.Port = "993"
	}

	return &config, nil
}

func (s *SyncTool) ensureSourceConnection() error {
	if s.source == nil {
		return s.reconnectSource()
	}

	// Test connection with NOOP
	if err := s.source.Noop(); err != nil {
		log.Printf("Source connection lost, reconnecting: %v", err)
		return s.reconnectSource()
	}
	return nil
}

func (s *SyncTool) ensureDestConnection() error {
	if s.dest == nil || s.outputDir != "" {
		return nil // No destination needed for file output
	}

	// Test connection with NOOP
	if err := s.dest.Noop(); err != nil {
		log.Printf("Destination connection lost, reconnecting: %v", err)
		return s.reconnectDest()
	}
	return nil
}

func (s *SyncTool) reconnectSource() error {
	if s.source != nil {
		s.source.Logout()
	}

	var err error
	s.source, err = connect(s.srcConfig)
	if err != nil {
		return fmt.Errorf("failed to reconnect to source: %v", err)
	}
	log.Printf("Successfully reconnected to source")
	return nil
}

func (s *SyncTool) reconnectDest() error {
	if s.dest != nil {
		s.dest.Logout()
	}

	var err error
	s.dest, err = connect(s.destConfig)
	if err != nil {
		return fmt.Errorf("failed to reconnect to destination: %v", err)
	}
	log.Printf("Successfully reconnected to destination")
	return nil
}

func sanitizeFilename(input string) string {
	// Remove or replace invalid filename characters
	invalidChars := regexp.MustCompile(`[<>:"/\\|?*\x00-\x1F]`)
	sanitized := invalidChars.ReplaceAllString(input, "_")

	// Replace spaces with underscores
	sanitized = strings.ReplaceAll(sanitized, " ", "_")

	// Limit length to avoid filesystem issues
	if len(sanitized) > 100 {
		sanitized = sanitized[:100]
	}

	return sanitized
}

func (s *SyncTool) printFinalStats() {
	log.Printf("\n=== Sync Complete ===")
	log.Printf("Total mailboxes: %d", s.stats.TotalMailboxes)
	log.Printf("Total messages: %d", s.stats.TotalMessages)
	log.Printf("Copied messages: %d", s.stats.CopiedMessages)
	log.Printf("Skipped messages: %d", s.stats.SkippedMessages)
	if s.stats.Errors > 0 {
		log.Printf("Errors: %d", s.stats.Errors)
	}
}

func (s *SyncTool) syncAll(dryRun bool) error {
	// List mailboxes from source
	mailboxes := make(chan *imap.MailboxInfo, 10)
	done := make(chan error, 1)
	go func() {
		done <- s.source.List("", "*", mailboxes)
	}()

	var mbxList []*imap.MailboxInfo
	for m := range mailboxes {
		mbxList = append(mbxList, m)
	}

	if err := <-done; err != nil {
		return fmt.Errorf("failed to list mailboxes: %v", err)
	}

	s.stats.TotalMailboxes = len(mbxList)
	log.Printf("Found %d mailboxes to sync", s.stats.TotalMailboxes)

	for i, mbx := range mbxList {
		log.Printf("[%d/%d] Processing mailbox: %s", i+1, len(mbxList), mbx.Name)
		if err := s.syncMailbox(mbx.Name, dryRun); err != nil {
			log.Printf("Failed to sync mailbox %s: %v", mbx.Name, err)
			s.stats.Errors++
			continue
		}
	}

	return nil
}

func (s *SyncTool) syncMailbox(mailboxName string, dryRun bool) error {
	// Ensure connections are alive
	if err := s.ensureSourceConnection(); err != nil {
		return fmt.Errorf("source connection failed: %v", err)
	}
	if err := s.ensureDestConnection(); err != nil {
		return fmt.Errorf("destination connection failed: %v", err)
	}

	// Select source mailbox
	srcMbox, err := s.source.Select(mailboxName, true) // read-only
	if err != nil {
		return fmt.Errorf("failed to select source mailbox: %v", err)
	}

	if srcMbox.Messages == 0 {
		log.Printf("  No messages in source mailbox")
		return nil
	}

	s.stats.TotalMessages += int(srcMbox.Messages)
	log.Printf("  Found %d messages", srcMbox.Messages)

	// Get existing message IDs from destination
	destMessageIDs := make(map[string]bool)
	var destMbox *imap.MailboxStatus

	if s.outputDir == "" {
		// IMAP destination mode
		if !dryRun {
			s.dest.Create(mailboxName) // Ignore error if it already exists
		}

		destMbox, err = s.dest.Select(mailboxName, false)
		if err != nil {
			if !dryRun {
				return fmt.Errorf("failed to select destination mailbox: %v", err)
			}
			destMbox = &imap.MailboxStatus{Messages: 0}
		}

		if destMbox.Messages > 0 {
			seqset := new(imap.SeqSet)
			seqset.AddRange(1, destMbox.Messages)

			messages := make(chan *imap.Message, 10)
			done := make(chan error, 1)
			go func() {
				done <- s.dest.Fetch(seqset, []imap.FetchItem{imap.FetchEnvelope}, messages)
			}()

			for msg := range messages {
				if msg.Envelope != nil && msg.Envelope.MessageId != "" {
					destMessageIDs[msg.Envelope.MessageId] = true
				}
			}

			if err := <-done; err != nil {
				return fmt.Errorf("failed to fetch destination messages: %v", err)
			}
		}
	} else {
		// File output mode - create directory structure
		mailboxDir := filepath.Join(s.outputDir, sanitizeFilename(mailboxName))
		if !dryRun {
			if err := os.MkdirAll(mailboxDir, 0755); err != nil {
				return fmt.Errorf("failed to create mailbox directory: %v", err)
			}
		}

		// Check existing EML files
		if !dryRun {
			files, err := filepath.Glob(filepath.Join(mailboxDir, "*.eml"))
			if err == nil {
				for _, file := range files {
					basename := filepath.Base(file)
					// Extract message-id-like identifier from filename for deduplication
					destMessageIDs[basename] = true
				}
			}
		}
	}

	log.Printf("  Start Processing %d messages", srcMbox.Messages)
	// Process source messages in batches
	const batchSize = 100
	copied := 0
	skipped := 0

	for start := uint32(1); start <= srcMbox.Messages; start += batchSize {
		end := start + batchSize - 1
		if end > srcMbox.Messages {
			end = srcMbox.Messages
		}

		// Periodic connection check every 10 batches
		if (start-1)/batchSize%10 == 0 && start > 1 {
			if err := s.ensureSourceConnection(); err != nil {
				log.Printf("Source connection check failed: %v", err)
				continue
			}
			if err := s.ensureDestConnection(); err != nil {
				log.Printf("Destination connection check failed: %v", err)
				continue
			}
		}

		seqset := new(imap.SeqSet)
		seqset.AddRange(start, end)

		log.Printf("  Downloading batch %s\n", seqset.String())
		messages := make(chan *imap.Message, 10)
		done := make(chan error, 1)
		go func() {
			done <- s.source.Fetch(seqset, []imap.FetchItem{
				imap.FetchEnvelope,
				imap.FetchRFC822,
				imap.FetchFlags,
				imap.FetchInternalDate,
			}, messages)
		}()

		for msg := range messages {
			if msg.Envelope == nil || msg.Envelope.MessageId == "" {
				log.Printf("  Skipping message without Message-ID")
				skipped++
				s.stats.SkippedMessages++
				continue
			}

			messageID := msg.Envelope.MessageId

			// Create filename for file output mode
			var filename string
			if s.outputDir != "" {

				date := msg.InternalDate
				if date.IsZero() && !msg.Envelope.Date.IsZero() {
					date = msg.Envelope.Date
				}
				if date.IsZero() {
					date = time.Now()
				}

				subject := sanitizeFilename(msg.Envelope.Subject)
				from := ""
				if len(msg.Envelope.From) > 0 && msg.Envelope.From[0].PersonalName != "" {
					from = sanitizeFilename(msg.Envelope.From[0].PersonalName)
				} else if len(msg.Envelope.From) > 0 && msg.Envelope.From[0].MailboxName != "" {
					from = sanitizeFilename(msg.Envelope.From[0].MailboxName)
				}

				filename = fmt.Sprintf("%s_%s_%s.eml",
					date.Format("20060102_150405"),
					subject,
					from)

				if destMessageIDs[filename] {
					skipped++
					s.stats.SkippedMessages++
					continue
				}

			} else {
				if destMessageIDs[messageID] {
					skipped++
					s.stats.SkippedMessages++
					continue
				}
			}
			log.Printf("  Processing Message %s\n", messageID)

			if dryRun {
				if s.outputDir != "" {
					log.Printf("  Would save: %s", filename)
				} else {
					log.Printf("  Would copy: %s (Subject: %s)", messageID, msg.Envelope.Subject)
				}
				copied++
				s.stats.CopiedMessages++
				continue
			}

			// Copy/save message with retry
			if s.outputDir != "" {
				if err := s.saveMessageToFile(msg, mailboxName, filename); err != nil {
					log.Printf("  Failed to save message %s: %v", filename, err)
					s.stats.Errors++
					continue
				}
				destMessageIDs[filename] = true
			} else {
				if err := s.copyMessageWithRetry(msg, mailboxName, messageID); err != nil {
					log.Printf("  Failed to copy message %s after retries: %v", messageID, err)
					s.stats.Errors++
					continue
				}
				destMessageIDs[messageID] = true
			}

			copied++
			s.stats.CopiedMessages++
		}

		if err := <-done; err != nil {
			return fmt.Errorf("failed to fetch source messages: %v", err)
		}
	}

	log.Printf("  Copied: %d, Skipped: %d", copied, skipped)
	return nil
}

func (s *SyncTool) copyMessage(msg *imap.Message, mailboxName string) error {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic while copying message: %v", r)
		}
	}()
	if msg.Body == nil {
		return fmt.Errorf("message body is nil")
	}

	// Find the RFC822 body section
	var msgBody io.Reader
	for section, body := range msg.Body {
		if section != nil && section.Specifier == imap.TextSpecifier {
			msgBody = body
			break
		}
	}

	// If no text section found, try any available body section
	if msgBody == nil {
		for _, body := range msg.Body {
			if body != nil {
				msgBody = body
				break
			}
		}
	}

	if msgBody == nil {
		return fmt.Errorf("no valid body section found")
	}

	// Parse the message with charset fallback
	entity, err := parseMessageWithFallback(msgBody, msg.Envelope.MessageId)
	var buf strings.Builder

	if err != nil && strings.Contains(err.Error(), "charset_error") {
		// Charset error - copy raw content without parsing
		log.Printf("  Using raw copy for message %s due to charset issues", msg.Envelope.MessageId)
		if _, err := io.Copy(&buf, msgBody); err != nil {
			return fmt.Errorf("failed to copy raw message: %v", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to parse message: %v", err)
	} else {
		// Normal parsing successful
		if err := entity.WriteTo(&buf); err != nil {
			return fmt.Errorf("failed to write message: %v", err)
		}
	}

	// Append to destination mailbox
	flags := msg.Flags
	date := msg.InternalDate
	if date.IsZero() {
		date = time.Now()
	}

	log.Printf("  Copy Message %s\n", msg.Envelope.MessageId)

	return s.dest.Append(mailboxName, flags, date, strings.NewReader(buf.String()))
}

func (s *SyncTool) copyMessageWithRetry(msg *imap.Message, mailboxName, messageID string) error {
	const maxRetries = 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			log.Printf("  Retry %d/%d for message %s", attempt, maxRetries, messageID)
			// Ensure connections are alive before retry
			if err := s.ensureDestConnection(); err != nil {
				log.Printf("  Connection check failed on retry %d: %v", attempt, err)
				continue
			}
		}

		err := s.copyMessage(msg, mailboxName)
		if err == nil {
			if attempt > 1 {
				log.Printf("  Successfully copied message %s on retry %d", messageID, attempt)
			}
			return nil
		}

		// Check if it's a connection-related error
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "not logged in") ||
			strings.Contains(errStr, "connection") ||
			strings.Contains(errStr, "timeout") {
			log.Printf("  Connection error on attempt %d: %v", attempt, err)
			if attempt < maxRetries {
				time.Sleep(time.Duration(attempt) * time.Second) // Backoff
				continue
			}
		}

		// Non-retryable error or max retries exceeded
		return err
	}

	return fmt.Errorf("failed after %d attempts", maxRetries)
}

func (s *SyncTool) saveMessageToFile(msg *imap.Message, mailboxName, filename string) error {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic while saving message: %v", r)
		}
	}()
	log.Printf("  Writing Message to %s id:%v\n", filename, msg.Envelope.MessageId)
	if msg.Body == nil {
		return fmt.Errorf("message body is nil")
	}

	// Find the RFC822 body section
	var msgBody io.Reader
	for section, body := range msg.Body {
		if section != nil && section.Specifier == imap.TextSpecifier {
			msgBody = body
			break
		}
	}

	// If no text section found, try any available body section
	if msgBody == nil {
		for _, body := range msg.Body {
			if body != nil {
				msgBody = body
				break
			}
		}
	}

	if msgBody == nil {
		return fmt.Errorf("no valid body section found")
	}

	// Parse the message with charset fallback
	entity, err := parseMessageWithFallback(msgBody, msg.Envelope.MessageId)

	// Create the full file path
	mailboxDir := filepath.Join(s.outputDir, sanitizeFilename(mailboxName))
	filePath := filepath.Join(mailboxDir, filename)

	// Create the file
	file, err2 := os.Create(filePath)
	if err2 != nil {
		return fmt.Errorf("failed to create file: %v", err2)
	}
	defer file.Close()

	// Write the message content to file
	if err != nil && strings.Contains(err.Error(), "charset_error") {
		// Charset error - copy raw content without parsing
		log.Printf("  Using raw copy for file %s due to charset issues", filename)
		if _, err := io.Copy(file, msgBody); err != nil {
			return fmt.Errorf("failed to copy raw message to file: %v", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to parse message: %v", err)
	} else {
		// Normal parsing successful
		if err := entity.WriteTo(file); err != nil {
			return fmt.Errorf("failed to write message to file: %v", err)
		}
	}

	return nil
}

func parseMessageWithFallback(msgBody io.Reader, messageID string) (*message.Entity, error) {
	// First attempt: normal parsing
	entity, err := message.Read(msgBody)
	if err == nil {
		return entity, nil
	}

	// Check if it's a charset error
	if strings.Contains(err.Error(), "charset") || strings.Contains(err.Error(), "unknown charset") {
		log.Printf("  Charset error for message %s, attempting raw copy: %v", messageID, err)

		// For charset errors, we'll skip parsing and return nil
		// The calling function should handle raw copying
		return nil, fmt.Errorf("charset_error: %w", err)
	}

	// Other errors, return as-is
	return nil, err
}
