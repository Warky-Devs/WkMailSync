# WkMailSync

A IMAP mail synchronization and backup tool written in Go. WkMailSync allows you to sync emails between IMAP servers or export them to local EML files with advanced filtering and organization features.

## Features

- **IMAP to IMAP Sync**: Synchronize emails between different IMAP servers
- **Export to EML Files**: Save emails as individual EML files for local backup
- **Date Range Filtering**: Sync only messages within specified date ranges
- **Subdirectory Organization**: Copy emails to a subdirectory while preserving folder structure (e.g., Archive/INBOX, Archive/Sent)
- **Automatic Hierarchy Detection**: Detects and uses the correct IMAP folder separator for each server
- **Robust Error Handling**: Handles malformed emails, charset issues, and connection problems gracefully
- **Deduplication**: Skips messages that already exist in the destination
- **Connection Recovery**: Automatically reconnects on connection failures
- **Comprehensive Logging**: Detailed progress reporting and error logging
- **Batch Processing**: Processes messages in batches to optimize performance
- **Dry Run Mode**: Preview what would be synced without making changes

## Installation

### Prerequisites

- Go 1.24.6 or later

### Build from Source

```bash
git clone https://github.com/Warky-Devs/WkMailSync.git
cd WkMailSync
go build ./cmd/WKMailSync
```

## Usage

### Command Line Usage

#### Basic IMAP to IMAP Sync
```bash
./WKMailSync \
  -src-host source.imap.com -src-user user@source.com -src-pass password1 \
  -dest-host dest.imap.com -dest-user user@dest.com -dest-pass password2
```

#### Export to EML Files
```bash
./WKMailSync \
  -src-host source.imap.com -src-user user@source.com -src-pass password \
  -output-dir /path/to/backup/folder
```

#### Sync with Date Range Filtering
```bash
./WKMailSync \
  -src-host source.imap.com -src-user user@source.com -src-pass password1 \
  -dest-host dest.imap.com -dest-user user@dest.com -dest-pass password2 \
  -date-from "2024-01-01" -date-to "2024-12-31"
```

#### Archive Old Emails to Subdirectory
```bash
./WKMailSync \
  -src-host source.imap.com -src-user user@source.com -src-pass password1 \
  -dest-host dest.imap.com -dest-user user@dest.com -dest-pass password2 \
  -subdirectory "Archive" -date-to "2023-12-31"
```

### Configuration File Usage

Create a YAML configuration file for easier management:

```yaml
# config.yaml
source:
  host: "mail.oldprovider.com"
  port: "993"
  username: "user@oldprovider.com"
  password: "oldpassword"
  use_tls: true
  insecure_tls: false

destination:
  host: "mail.newprovider.com"
  port: "993"
  username: "user@newprovider.com"  
  password: "newpassword"
  use_tls: true
  insecure_tls: false

# Alternative: export to EML files instead of IMAP destination
# output_dir: "/home/user/mail-backup"

# Optional: subdirectory in destination to preserve source structure
subdirectory: "Archive"

# Optional: date range filtering
date_from: "2024-01-01"
date_to: "2024-12-31"

dry_run: false
```

Then run:
```bash
./WKMailSync -config config.yaml
```

## Command Line Options

| Flag | Description | Example |
|------|-------------|---------|
| `-config` | YAML config file path | `-config config.yaml` |
| `-src-host` | Source IMAP host | `-src-host mail.gmail.com` |
| `-src-port` | Source IMAP port (default: 993) | `-src-port 993` |
| `-src-user` | Source username | `-src-user user@gmail.com` |
| `-src-pass` | Source password | `-src-pass mypassword` |
| `-src-tls` | Use TLS for source (default: true) | `-src-tls=false` |
| `-src-insecure` | Skip certificate verification for source | `-src-insecure` |
| `-dest-host` | Destination IMAP host | `-dest-host mail.fastmail.com` |
| `-dest-port` | Destination IMAP port (default: 993) | `-dest-port 993` |
| `-dest-user` | Destination username | `-dest-user user@fastmail.com` |
| `-dest-pass` | Destination password | `-dest-pass mypassword` |
| `-dest-tls` | Use TLS for destination (default: true) | `-dest-tls=false` |
| `-dest-insecure` | Skip certificate verification for destination | `-dest-insecure` |
| `-output-dir` | Output directory for EML files (alternative to IMAP) | `-output-dir /backup/mail` |
| `-subdirectory` | Subdirectory in destination for organized copying | `-subdirectory Archive` |
| `-date-from` | Only sync messages from this date onwards | `-date-from "2024-01-01"` |
| `-date-to` | Only sync messages up to this date | `-date-to "2024-12-31"` |
| `-dry-run` | Show what would be synced without doing it | `-dry-run` |

## Date Format Support

Date filtering supports multiple formats:

- `2006-01-02` (YYYY-MM-DD)
- `2006-01-02T15:04:05` (YYYY-MM-DDTHH:MM:SS)
- `2006-01-02 15:04:05` (YYYY-MM-DD HH:MM:SS)
- `2006-01-02T15:04:05Z` (UTC)
- `2006-01-02T15:04:05Z07:00` (RFC3339 with timezone)

## Use Cases

### Email Provider Migration
Migrate all your emails from one provider to another:
```bash
./WKMailSync -config migration.yaml
```

### Periodic Backups
Create local EML backups of your emails:
```bash
./WKMailSync \
  -src-host imap.gmail.com -src-user you@gmail.com -src-pass yourpass \
  -output-dir /backup/gmail-$(date +%Y%m%d)
```

### Archive Old Emails
Move old emails to an Archive folder:
```bash
./WKMailSync \
  -src-host imap.gmail.com -src-user you@gmail.com -src-pass pass1 \
  -dest-host imap.gmail.com -dest-user you@gmail.com -dest-pass pass1 \
  -subdirectory "Archive" -date-to "2023-12-31"
```

### Selective Sync
Sync only recent emails (e.g., last 6 months):
```bash
./WKMailSync \
  -src-host old-server.com -src-user you@old.com -src-pass pass1 \
  -dest-host new-server.com -dest-user you@new.com -dest-pass pass2 \
  -date-from "2024-06-01"
```

## Error Handling

WkMailSync handles various email and server issues gracefully:

- **Malformed MIME Messages**: Uses raw copy when parsing fails
- **Missing Message-IDs**: Generates unique IDs for deduplication
- **Charset Issues**: Falls back to raw copying for unknown charsets
- **Connection Failures**: Automatically reconnects and retries
- **Server Differences**: Detects and adapts to different IMAP folder separators

## Logging

The tool provides comprehensive logging:

```
Found 5 mailboxes to sync
[1/5] Processing mailbox: INBOX
  Found 1250 messages
  Downloading batch 1:100
  Processing Message <abc123@example.com>
  Copy Message <abc123@example.com>
  Copied: 95, Skipped: 5

=== Sync Complete ===
Total mailboxes: 5
Total messages: 3420
Copied messages: 3200
Skipped messages: 220
```

## Performance

- Processes messages in configurable batches (default: 100)
- Maintains persistent connections to both servers
- Implements connection pooling and recovery
- Uses efficient deduplication based on Message-ID
- Handles large mailboxes without memory issues

## Troubleshooting

### Common Issues

**"Failed to connect"**
- Verify host, port, username, and password
- Check if TLS is required (`-src-tls` or `-dest-tls`)
- For self-signed certificates, use `-src-insecure` or `-dest-insecure`

**"All goroutines are asleep - deadlock"**
- This issue has been resolved in recent versions
- Ensure you're using the latest build

**"Malformed MIME header"**
- The tool automatically handles these with raw copying
- No action needed from the user

**Date parsing errors**
- Ensure date format matches supported formats
- Use quotes around dates: `-date-from "2024-01-01"`

## Building

To build the project:

```bash
go mod tidy
go build ./cmd/WKMailSync
```

To run tests:
```bash
go test ./...
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Changelog

### Recent Improvements
- ✅ Fixed IMAP deadlock issues in message processing
- ✅ Added date range filtering for selective synchronization
- ✅ Implemented subdirectory organization with hierarchy detection
- ✅ Enhanced error handling for malformed emails and MIME issues
- ✅ Added automatic Message-ID generation for emails without IDs
- ✅ Improved connection recovery and retry mechanisms
- ✅ Added comprehensive charset support and fallback handling