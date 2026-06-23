## Project Overview

**WkMailSync** is a Go CLI tool for mail synchronization and backup. It syncs IMAP→IMAP, exports IMAP→EML/Zip, reads local Maildir sources, and bulk-exports all users from a Virtualmin server.

# Agent Rules

Keep your answers short. Question everything, never assume or guess. Ask the user if you are unsure about anything.

## AMCS MCP Tools

Use the AMCS MCP system tools. Always capture summaries of what was done as thoughts using the `capture_thought` tool.
If AMCS is not available, write logs to `doc/llm/log/YYYYMMDD_HH.md`.

Load the needed Go skill from AMCS when available.

# Tools to use

When writing Go code, follow standard Go idioms. The project has no ORM, no framework — it is pure Go with a small set of dependencies (see `go.mod`).

## Commands

```bash
go build ./cmd/wkmailsync        # Build the binary
go test ./...                    # Run all tests
go vet ./...                     # Static analysis
go fmt ./...                     # Format code
```

## Architecture

```
cmd/wkmailsync/      — CLI entry point (flags, config loading, mode dispatch)
pkg/config/          — Config structs, LoadConfig(), ParseDateString()
pkg/source/          — MailSource interface: IMAP + Maildir implementations
pkg/output/          — MailOutput interface: EML, Zip, IMAP implementations
pkg/sync/            — SyncEngine (source → output, date filtering, dedup, stats)
pkg/connector/       — VirtualminConnector interface: local/SSH/API implementations
```

### Mode selection

The active mode is determined by which top-level config key is present:

| Key present                | Mode                                           |
| -------------------------- | ---------------------------------------------- |
| `virtualmin:`              | Enumerate all Virtualmin users and export each |
| `maildir_source:`          | Read local Maildir directory                   |
| `source:` only             | IMAP → file (EML or Zip)                       |
| `source:` + `destination:` | IMAP → IMAP                                    |

### Key interfaces

- `pkg/source/source.go` — `MailSource` interface (Connect, ListFolders, FetchMessages, Close)
- `pkg/output/output.go` — `MailOutput` interface (Connect, SaveMessage, Close)
- `pkg/connector/connector.go` — `VirtualminConnector` interface (ListDomains, ListMailboxes, GetMaildirPath)
- `pkg/sync/sync.go` — `SyncEngine` orchestrates source → output with filtering and dedup

### Minimal programmatic sync

```go
src, _ := source.NewIMAPSource(cfg.Source)
out, _ := output.NewEMLOutput(cfg.OutputDir)
engine := sync.NewSyncEngine(src, out)
engine.DateFrom = dateFrom
engine.DateTo   = dateTo
engine.DryRun   = true
engine.Run()
engine.PrintStats()
```

## Output structure

- **EML**: `output_dir/FolderName/YYYYMMDD_HHMMSS_Subject_From.eml`
- **Zip**: `output_dir/username_YYYYMMDD_HHMMSS.zip` containing `FolderName/YYYYMMDD_HHMMSS_Subject_From.eml`

## Config reference

```yaml
source:
  host: mail.example.com
  port: "993"
  username: user@example.com
  password: secret
  use_tls: true
  insecure_tls: false

destination: # omit for file output
  host: mail2.example.com
  port: "993"
  username: user@example.com
  password: secret
  use_tls: true

output_dir: /backup/mail # required for file output
output_format: eml # eml | zip
subdirectory: Archive # optional folder prefix
date_from: "2024-01-01"
date_to: "2024-12-31"
dry_run: false

folder_include: [INBOX, Sent] # whitelist; empty = all
folder_exclude: [Spam, Trash] # blacklist; ignored if folder_include set

# Maildir source (replaces source:)
maildir_source:
  path: /home/user/Maildir
  user: user
  domain: example.com

# Virtualmin (replaces source: and maildir_source:)
virtualmin:
  mode: local | ssh | api
  domain: example.com # optional filter
  maildir_base: "" # default /home/%s/homes/%s/Maildir
  workers: 4

  ssh:
    host: server.example.com
    port: "22"
    username: root
    key_file: /home/user/.ssh/id_rsa

  api:
    host: server.example.com
    port: "10000"
    username: admin
    password: secret
    use_tls: true
    insecure_tls: false
    ssh:
      host: server.example.com
      username: root
      key_file: /home/user/.ssh/id_rsa
```
