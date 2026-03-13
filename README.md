# WkMailSync

Mail synchronization and backup tool in Go. Syncs IMAP→IMAP, IMAP→EML, Maildir→EML/Zip, or bulk-exports all users from a Virtualmin server.

## Features

- IMAP→IMAP sync with deduplication
- IMAP→EML or IMAP→Zip export
- Local Maildir as source
- Virtualmin integration — enumerate domains/users via local CLI, SSH, or HTTP API
- Zip output — one archive per user
- Date range filtering
- Subdirectory organization with auto-detected IMAP separator
- Dry-run mode
- Charset fallback, malformed MIME handling, auto-reconnect

## Build

```bash
git clone https://github.com/Warky-Devs/WkMailSync.git
cd WkMailSync
go build ./cmd/WKMailSync
```

Requires Go 1.24+.

## Quick Start

```bash
# IMAP → IMAP
./WKMailSync -src-host src.example.com -src-user u@src.com -src-pass p1 \
             -dest-host dst.example.com -dest-user u@dst.com -dest-pass p2

# IMAP → EML files
./WKMailSync -src-host src.example.com -src-user u@src.com -src-pass p1 \
             -output-dir /backup/mail

# IMAP → Zip
./WKMailSync -src-host src.example.com -src-user u@src.com -src-pass p1 \
             -output-dir /backup -output-format zip

# Maildir → EML files
./WKMailSync -config maildir.yaml

# Maildir → Zip
./WKMailSync -config maildir-zip.yaml

# Config file
./WKMailSync -config config.yaml
```

### Maildir examples

`maildir.yaml` — export a local Maildir to EML files:
```yaml
maildir_source:
  path: "/home/user/Maildir"
  user: "user"
  domain: "example.com"

output_dir: "/backup/mail"
dry_run: false
```

`maildir-zip.yaml` — same but compressed:
```yaml
maildir_source:
  path: "/home/user/Maildir"
  user: "user"
  domain: "example.com"

output_dir: "/backup"
output_format: "zip"
```

Date filtering works with Maildir too:
```yaml
maildir_source:
  path: "/home/user/Maildir"

output_dir: "/backup/mail"
date_from: "2024-01-01"
date_to: "2024-12-31"
```

## Config File

```yaml
source:
  host: "mail.example.com"
  port: "993"
  username: "user@example.com"
  password: "secret"
  use_tls: true
  insecure_tls: false

# IMAP destination (optional — omit if using output_dir)
destination:
  host: "mail2.example.com"
  port: "993"
  username: "user@example.com"
  password: "secret"
  use_tls: true

output_dir: "/backup/mail"   # omit for IMAP destination
output_format: "eml"         # eml (default) | zip
subdirectory: ""             # e.g. "Archive" → Archive/INBOX, Archive/Sent
date_from: "2024-01-01"      # optional
date_to: "2024-12-31"        # optional
dry_run: false
```

### Maildir Source

Read directly from a local Maildir directory instead of IMAP:

```yaml
maildir_source:
  path: "/home/user/Maildir"
  domain: "example.com"
  user: "user"

output_dir: "/backup/mail"
output_format: "zip"
```

### Virtualmin Integration

Enumerate all domains and users, then sync each user's Maildir.

**Local** (run on the Virtualmin server itself):
```yaml
virtualmin:
  mode: "local"
  domain: ""             # optional: filter to one domain
  maildir_base: ""       # optional: default /home/%s/homes/%s/Maildir

output_dir: "/backup/mail"
output_format: "zip"
```

**SSH** (run remotely):
```yaml
virtualmin:
  mode: "ssh"
  ssh:
    host: "server.example.com"
    port: "22"
    username: "root"
    key_file: "/home/user/.ssh/id_rsa"
    # password: "secret"   # alternative to key_file

output_dir: "/backup/mail"
output_format: "zip"
```

**API** (Webmin HTTP API):
```yaml
virtualmin:
  mode: "api"
  api:
    host: "server.example.com"
    port: "10000"
    username: "admin"
    password: "secret"
    use_tls: true
    insecure_tls: false
    ssh:                          # for reading mail over SFTP
      host: "server.example.com"
      username: "root"
      key_file: "/home/user/.ssh/id_rsa"

output_dir: "/backup/mail"
output_format: "zip"
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | | YAML config file |
| `-src-host` | | Source IMAP host |
| `-src-port` | `993` | Source IMAP port |
| `-src-user` | | Source username |
| `-src-pass` | | Source password |
| `-src-tls` | `true` | TLS for source |
| `-src-insecure` | `false` | Skip cert verification |
| `-dest-host` | | Destination IMAP host |
| `-dest-port` | `993` | Destination IMAP port |
| `-dest-user` | | Destination username |
| `-dest-pass` | | Destination password |
| `-dest-tls` | `true` | TLS for destination |
| `-dest-insecure` | `false` | Skip cert verification |
| `-output-dir` | | Output directory (EML/Zip) |
| `-output-format` | `eml` | `eml` or `zip` |
| `-subdirectory` | | Destination subdirectory prefix |
| `-date-from` | | Sync messages from date |
| `-date-to` | | Sync messages up to date |
| `-dry-run` | `false` | Preview without changes |

## Date Formats

`YYYY-MM-DD` · `YYYY-MM-DDTHH:MM:SS` · `YYYY-MM-DD HH:MM:SS` · RFC3339

## Output Structure

**EML**: `output_dir/FolderName/YYYYMMDD_HHMMSS_Subject_From.eml`

**Zip**: `output_dir/username_YYYYMMDD_HHMMSS.zip` with `FolderName/YYYYMMDD_HHMMSS_Subject_From.eml` inside

## Package Structure

```
cmd/WKMailSync/main.go     — CLI entry point
pkg/config/                — Config structs + YAML loading
pkg/source/                — MailSource interface, IMAP + Maildir implementations
pkg/output/                — MailOutput interface, EML + Zip + IMAP implementations
pkg/sync/                  — SyncEngine (source → output, filtering, dedup, stats)
pkg/connector/             — VirtualminConnector interface, local/SSH/API implementations
```

## Troubleshooting

**Connection refused / TLS error** — check host, port, `use_tls`, try `insecure_tls: true` for self-signed certs.

**Malformed MIME / charset errors** — handled automatically with raw fallback copy.

**Virtualmin CLI not found** — `local` mode requires `virtualmin` binary in PATH on the target machine.

## License

MIT
