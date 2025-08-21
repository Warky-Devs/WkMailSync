package main

import (
	"bytes"
	"crypto/sha256"
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
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/unicode"
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
	Source       ServerConfig `yaml:"source"`
	Dest         ServerConfig `yaml:"destination"`
	OutputDir    string       `yaml:"output_dir"`
	DryRun       bool         `yaml:"dry_run"`
	Subdirectory string       `yaml:"subdirectory"`
	DateFrom     string       `yaml:"date_from"`
	DateTo       string       `yaml:"date_to"`
}

type SyncStats struct {
	TotalMailboxes  int
	TotalMessages   int
	CopiedMessages  int
	SkippedMessages int
	Errors          int
}

type SyncTool struct {
	source        *client.Client
	dest          *client.Client
	outputDir     string
	stats         *SyncStats
	srcConfig     ServerConfig
	destConfig    ServerConfig
	subdirectory  string
	destSeparator string    // IMAP hierarchy separator for destination server
	dateFrom      time.Time // Start date for filtering messages
	dateTo        time.Time // End date for filtering messages
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

		dryRun       = flag.Bool("dry-run", false, "Show what would be synced without actually doing it")
		outputDir    = flag.String("output-dir", "", "Output directory for EML files (alternative to IMAP destination)")
		subdirectory = flag.String("subdirectory", "", "Optional subdirectory in destination to preserve source structure (e.g., 'Archive')")
		dateFrom     = flag.String("date-from", "", "Only sync messages from this date onwards (format: 2006-01-02 or 2006-01-02T15:04:05)")
		dateTo       = flag.String("date-to", "", "Only sync messages up to this date (format: 2006-01-02 or 2006-01-02T15:04:05)")
	)
	flag.Parse()

	var srcConfig, destConfig ServerConfig
	var dryRunFlag bool
	var outputDirFlag string
	var subdirectoryFlag string
	var dateFromFlag, dateToFlag string

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
		subdirectoryFlag = config.Subdirectory
		dateFromFlag = config.DateFrom
		dateToFlag = config.DateTo
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
		subdirectoryFlag = *subdirectory
		dateFromFlag = *dateFrom
		dateToFlag = *dateTo
	}

	// Parse date ranges if provided
	var dateFromParsed, dateToParsed time.Time
	if dateFromFlag != "" {
		var err error
		dateFromParsed, err = parseDateString(dateFromFlag)
		if err != nil {
			log.Fatalf("Invalid date-from format: %v (use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)", err)
		}
	}
	if dateToFlag != "" {
		var err error
		dateToParsed, err = parseDateString(dateToFlag)
		if err != nil {
			log.Fatalf("Invalid date-to format: %v (use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)", err)
		}
	}
	
	// Validate date range
	if !dateFromParsed.IsZero() && !dateToParsed.IsZero() && dateFromParsed.After(dateToParsed) {
		log.Fatalf("date-from cannot be after date-to")
	}

	syncer := &SyncTool{
		outputDir:    outputDirFlag,
		stats:        &SyncStats{},
		srcConfig:    srcConfig,
		destConfig:   destConfig,
		subdirectory: subdirectoryFlag,
		dateFrom:     dateFromParsed,
		dateTo:       dateToParsed,
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
		
		// Detect IMAP hierarchy separator for subdirectory feature
		if syncer.subdirectory != "" {
			if err := syncer.detectDestinationSeparator(); err != nil {
				log.Fatalf("Failed to detect destination separator: %v", err)
			}
		}
	}

	// Log sync configuration
	if !syncer.dateFrom.IsZero() || !syncer.dateTo.IsZero() {
		log.Printf("Date filtering enabled:")
		if !syncer.dateFrom.IsZero() {
			log.Printf("  From: %s", syncer.dateFrom.Format("2006-01-02 15:04:05"))
		}
		if !syncer.dateTo.IsZero() {
			log.Printf("  To: %s", syncer.dateTo.Format("2006-01-02 15:04:05"))
		}
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
	
	// Re-detect separator after reconnection if using subdirectory
	if s.subdirectory != "" {
		s.destSeparator = "" // Reset to force re-detection
		if err := s.detectDestinationSeparator(); err != nil {
			return fmt.Errorf("failed to re-detect destination separator: %v", err)
		}
	}
	
	return nil
}

func (s *SyncTool) detectDestinationSeparator() error {
	if s.dest == nil || s.destSeparator != "" {
		return nil // Already detected or not needed
	}

	// Use LIST command to detect hierarchy separator
	mailboxes := make(chan *imap.MailboxInfo, 1)
	done := make(chan error, 1)
	go func() {
		done <- s.dest.List("", "", mailboxes)
	}()

	// Get the first mailbox info which contains the separator
	for m := range mailboxes {
		s.destSeparator = m.Delimiter
		break
	}

	if err := <-done; err != nil {
		return fmt.Errorf("failed to detect hierarchy separator: %v", err)
	}

	// Default to "/" if no separator detected
	if s.destSeparator == "" {
		s.destSeparator = "/"
	}

	log.Printf("Detected destination IMAP hierarchy separator: %q", s.destSeparator)
	return nil
}

func (s *SyncTool) buildDestinationMailboxPath(sourceMailboxName string) string {
	if s.subdirectory == "" {
		return sourceMailboxName
	}

	// Use the detected separator for the destination server
	// For example with "/": "INBOX" -> "Archive/INBOX"
	// For example with ".": "INBOX" -> "Archive.INBOX"
	return s.subdirectory + s.destSeparator + sourceMailboxName
}

func parseDateString(dateStr string) (time.Time, error) {
	// Try different date formats
	formats := []string{
		"2006-01-02",                // YYYY-MM-DD
		"2006-01-02T15:04:05",       // YYYY-MM-DDTHH:MM:SS
		"2006-01-02 15:04:05",       // YYYY-MM-DD HH:MM:SS
		"2006-01-02T15:04:05Z07:00", // RFC3339
		"2006-01-02T15:04:05Z",      // UTC
	}
	
	for _, format := range formats {
		if parsed, err := time.Parse(format, dateStr); err == nil {
			return parsed, nil
		}
	}
	
	return time.Time{}, fmt.Errorf("unable to parse date %q", dateStr)
}

func (s *SyncTool) shouldProcessMessage(msg *imap.Message) (bool, string) {
	// If no date filters are set, process all messages
	if s.dateFrom.IsZero() && s.dateTo.IsZero() {
		return true, ""
	}
	
	// Get message date - prefer InternalDate, fallback to envelope Date
	msgDate := msg.InternalDate
	if msgDate.IsZero() && msg.Envelope != nil && !msg.Envelope.Date.IsZero() {
		msgDate = msg.Envelope.Date
	}
	
	// Skip messages without valid dates if date filtering is enabled
	if msgDate.IsZero() {
		return false, "no valid date found"
	}
	
	// Check date range
	if !s.dateFrom.IsZero() && msgDate.Before(s.dateFrom) {
		return false, fmt.Sprintf("message date %s is before range start %s", msgDate.Format("2006-01-02"), s.dateFrom.Format("2006-01-02"))
	}
	
	if !s.dateTo.IsZero() && msgDate.After(s.dateTo) {
		return false, fmt.Sprintf("message date %s is after range end %s", msgDate.Format("2006-01-02"), s.dateTo.Format("2006-01-02"))
	}
	
	return true, ""
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

	// Build destination mailbox path (with optional subdirectory)
	destMailboxName := s.buildDestinationMailboxPath(mailboxName)

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
			s.dest.Create(destMailboxName) // Ignore error if it already exists
		}

		destMbox, err = s.dest.Select(destMailboxName, false)
		if err != nil {
			if !dryRun {
				return fmt.Errorf("failed to select destination mailbox %s: %v", destMailboxName, err)
			}
			destMbox = &imap.MailboxStatus{Messages: 0}
		}

		if destMbox.Messages > 0 {
			seqset := new(imap.SeqSet)
			seqset.AddRange(1, destMbox.Messages)

			messages := make(chan *imap.Message, int(destMbox.Messages)+10) // Buffer for all destination messages
			done := make(chan error, 1)
			go func() {
				done <- s.dest.Fetch(seqset, []imap.FetchItem{imap.FetchEnvelope}, messages)
			}()

			// Collect all destination messages first
			var destMessages []*imap.Message
			for msg := range messages {
				destMessages = append(destMessages, msg)
			}

			// Wait for fetch to complete
			if err := <-done; err != nil {
				return fmt.Errorf("failed to fetch destination messages: %v", err)
			}

			// Now process all destination messages
			for _, msg := range destMessages {
				if msg.Envelope != nil && msg.Envelope.MessageId != "" {
					destMessageIDs[msg.Envelope.MessageId] = true
				}
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
		messages := make(chan *imap.Message, int(end-start+1)+10) // Buffer for all messages in batch
		done := make(chan error, 1)
		go func() {
			done <- s.source.Fetch(seqset, []imap.FetchItem{
				imap.FetchEnvelope,
				imap.FetchRFC822,
				imap.FetchFlags,
				imap.FetchInternalDate,
			}, messages)
		}()

		// Collect all messages first to avoid deadlock
		var msgBatch []*imap.Message
		for msg := range messages {
			msgBatch = append(msgBatch, msg)
		}

		// Wait for fetch to complete
		if err := <-done; err != nil {
			return fmt.Errorf("failed to fetch source messages: %v", err)
		}

		// Now process all messages without blocking the fetch goroutine
		for _, msg := range msgBatch {
			if msg.Envelope == nil {
				log.Printf("  Skipping message with nil envelope (SeqNum: %d)", msg.SeqNum)
				skipped++
				s.stats.SkippedMessages++
				continue
			}
			
			// Check if message should be processed based on date range
			if shouldProcess, reason := s.shouldProcessMessage(msg); !shouldProcess {
				log.Printf("  Skipping message (SeqNum: %d): %s", msg.SeqNum, reason)
				skipped++
				s.stats.SkippedMessages++
				continue
			}
			
			// Generate fallback Message-ID for messages without one
			messageID := msg.Envelope.MessageId
			if messageID == "" {
				// Create a fallback Message-ID using subject, date, and sequence
				date := msg.InternalDate
				if date.IsZero() && !msg.Envelope.Date.IsZero() {
					date = msg.Envelope.Date
				}
				if date.IsZero() {
					date = time.Now()
				}
				
				subject := msg.Envelope.Subject
				if subject == "" {
					subject = "(no subject)"
				}
				
				// Generate unique ID: hash of subject + date + sequence number
				h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d-%d", subject, date.Unix(), msg.SeqNum)))
				messageID = fmt.Sprintf("<%x@wkmailsync.generated>", h[:8])
				log.Printf("  Generated Message-ID for message without one: %s (Subject: %q)", messageID, subject)
			}

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
				if err := s.copyMessageWithRetry(msg, destMailboxName, messageID); err != nil {
					log.Printf("  Failed to copy message %s after retries: %v", messageID, err)
					s.stats.Errors++
					continue
				}
				destMessageIDs[messageID] = true
			}

			copied++
			s.stats.CopiedMessages++
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

	// Read the entire message body into memory first to avoid consumption issues
	var msgContent bytes.Buffer
	if _, err := io.Copy(&msgContent, msgBody); err != nil {
		return fmt.Errorf("failed to read message body: %v", err)
	}
	
	// Parse the message with charset fallback
	entity, err := parseMessageWithFallback(bytes.NewReader(msgContent.Bytes()), msg.Envelope.MessageId)
	var buf strings.Builder

	if err != nil && strings.Contains(err.Error(), "charset_error") {
		// Parsing error (charset, MIME, etc.) - use raw content
		log.Printf("  Using raw copy for message %s due to parsing issues", msg.Envelope.MessageId)
		buf.Write(msgContent.Bytes())
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

	// Read the entire message body into memory first
	var msgContent bytes.Buffer
	if _, err := io.Copy(&msgContent, msgBody); err != nil {
		return fmt.Errorf("failed to read message body: %v", err)
	}
	
	// Parse the message with charset fallback
	entity, parseErr := parseMessageWithFallback(bytes.NewReader(msgContent.Bytes()), msg.Envelope.MessageId)

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
	if parseErr != nil && strings.Contains(parseErr.Error(), "charset_error") {
		// Parsing error (charset, MIME, etc.) - use raw content
		log.Printf("  Using raw copy for file %s due to parsing issues", filename)
		if _, err := file.Write(msgContent.Bytes()); err != nil {
			return fmt.Errorf("failed to copy raw message to file: %v", err)
		}
	} else if parseErr != nil {
		return fmt.Errorf("failed to parse message: %v", parseErr)
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
		return nil, fmt.Errorf("charset_error: %w", err)
	}

	// Check if it's a MIME parsing error (malformed headers, etc.)
	if strings.Contains(err.Error(), "malformed MIME") ||
		strings.Contains(err.Error(), "malformed header") ||
		strings.Contains(err.Error(), "invalid header") ||
		strings.Contains(err.Error(), "bad header") {
		log.Printf("  MIME parsing error for message %s, attempting raw copy: %v", messageID, err)
		return nil, fmt.Errorf("charset_error: %w", err) // Use same error type for consistency
	}

	// Other parsing errors - also try raw copy as fallback
	log.Printf("  Message parsing error for message %s, attempting raw copy: %v", messageID, err)
	return nil, fmt.Errorf("charset_error: %w", err)
}
