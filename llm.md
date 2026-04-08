# WkMailSync — LLM Usage Guide

## What it does
CLI tool to sync/export mail. Modes: IMAP→IMAP, IMAP→EML, IMAP→Zip, Maildir→EML/Zip, Virtualmin bulk export.

## Binary
```
wkmailsync [flags]
wkmailsync -config config.yaml
```

## Key flags
| Flag | Description |
|------|-------------|
| `-config <file>` | Load YAML config (preferred over inline flags) |
| `-src-host / -src-user / -src-pass` | Source IMAP credentials |
| `-dest-host / -dest-user / -dest-pass` | Destination IMAP (omit for file output) |
| `-output-dir <path>` | Write EML/Zip files here instead of IMAP |
| `-output-format eml\|zip` | Default: `eml` |
| `-date-from / -date-to` | Date filter, format `YYYY-MM-DD` |
| `-subdirectory <name>` | Prefix all destination folders |
| `-dry-run` | Preview only, no writes |
| `-generate-config imap\|maildir\|virtualmin` | Print example config and exit |
| `-v` | Print version and exit |

## Mode selection (config file)
The active mode is determined by which top-level key is present:

| Key present | Mode |
|-------------|------|
| `virtualmin:` | Enumerate all Virtualmin users and export each |
| `maildir_source:` | Read local Maildir directory |
| `source:` only (no `destination:`) | IMAP → file |
| `source:` + `destination:` | IMAP → IMAP |

## Config reference
```yaml
# IMAP source
source:
  host: mail.example.com
  port: "993"          # default 993
  username: user@example.com
  password: secret
  use_tls: true
  insecure_tls: false  # set true for self-signed certs

# IMAP destination (omit for file output)
destination:
  host: mail2.example.com
  port: "993"
  username: user@example.com
  password: secret
  use_tls: true

output_dir: /backup/mail   # required for file output
output_format: eml         # eml | zip
subdirectory: Archive      # optional folder prefix
date_from: "2024-01-01"
date_to:   "2024-12-31"
dry_run: false

folder_include: [INBOX, Sent]   # whitelist; empty = all
folder_exclude: [Spam, Trash]   # blacklist; ignored if folder_include set

# Maildir source (replaces source:)
maildir_source:
  path: /home/user/Maildir
  user: user
  domain: example.com

# Virtualmin (replaces source: and maildir_source:)
virtualmin:
  mode: local | ssh | api
  domain: example.com   # optional filter
  maildir_base: ""       # default /home/%s/homes/%s/Maildir
  workers: 4             # parallel domain workers

  # ssh mode
  ssh:
    host: server.example.com
    port: "22"
    username: root
    key_file: /home/user/.ssh/id_rsa
    # password: secret   # alternative

  # api mode
  api:
    host: server.example.com
    port: "10000"
    username: admin
    password: secret
    use_tls: true
    insecure_tls: false
    ssh:                 # for reading mail over SFTP
      host: server.example.com
      username: root
      key_file: /home/user/.ssh/id_rsa
```

## Output structure
- **EML**: `output_dir/FolderName/YYYYMMDD_HHMMSS_Subject_From.eml`
- **Zip**: `output_dir/username_YYYYMMDD_HHMMSS.zip` → `FolderName/YYYYMMDD_HHMMSS_Subject_From.eml`

## Date formats accepted
`YYYY-MM-DD` · `YYYY-MM-DDTHH:MM:SS` · `YYYY-MM-DD HH:MM:SS` · RFC3339

## Common tasks

**Backup one IMAP account to zip:**
```bash
wkmailsync -src-host mail.example.com -src-user u@example.com -src-pass p \
           -output-dir /backup -output-format zip
```

**Migrate between IMAP servers:**
```bash
wkmailsync -src-host src.example.com -src-user u@src.com -src-pass p1 \
           -dest-host dst.example.com -dest-user u@dst.com -dest-pass p2
```

**Dry-run a date-filtered backup:**
```bash
wkmailsync -config config.yaml -dry-run
```

**Bulk export all Virtualmin users:**
```bash
wkmailsync -config virtualmin.yaml   # must set virtualmin: in config
```

## Troubleshooting
- TLS/connection errors → check `use_tls`, try `insecure_tls: true`
- Virtualmin `local` mode → requires `virtualmin` binary in PATH on target host
- Malformed MIME → handled automatically with raw fallback

## Package structure (for programmatic use)
```
pkg/config/    Config structs, LoadConfig(), ParseDateString()
pkg/source/    MailSource interface — IMAP + Maildir implementations
pkg/output/    MailOutput interface — EML, Zip, IMAP implementations
pkg/sync/      SyncEngine{Source, Output, DateFrom, DateTo, DryRun}
pkg/connector/ VirtualminConnector interface — local/SSH/API implementations
cmd/wkmailsync CLI entry point
```

**Minimal programmatic sync:**
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
