package config

import (
	"os"
	"testing"
	"time"
)

func TestParseDateString(t *testing.T) {
	cases := []struct {
		input   string
		wantErr bool
		year    int
		month   time.Month
		day     int
	}{
		{"2024-01-15", false, 2024, 1, 15},
		{"2024-06-30T12:00:00", false, 2024, 6, 30},
		{"2024-06-30 12:00:00", false, 2024, 6, 30},
		{"2024-06-30T12:00:00Z", false, 2024, 6, 30},
		{"not-a-date", true, 0, 0, 0},
		{"", true, 0, 0, 0},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := ParseDateString(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Year() != tc.year || got.Month() != tc.month || got.Day() != tc.day {
				t.Errorf("got %v, want %d-%d-%d", got, tc.year, tc.month, tc.day)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	yaml := `
source:
  host: "imap.example.com"
  username: "user@example.com"
  password: "secret"
  use_tls: true
output_dir: "/tmp/mail"
output_format: "zip"
date_from: "2024-01-01"
date_to: "2024-12-31"
dry_run: true
`
	f, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(yaml)
	f.Close()

	cfg, err := LoadConfig(f.Name())
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Source.Host != "imap.example.com" {
		t.Errorf("Source.Host = %q", cfg.Source.Host)
	}
	if cfg.Source.Port != "993" {
		t.Errorf("Source.Port default = %q, want 993", cfg.Source.Port)
	}
	if cfg.OutputDir != "/tmp/mail" {
		t.Errorf("OutputDir = %q", cfg.OutputDir)
	}
	if cfg.OutputFormat != "zip" {
		t.Errorf("OutputFormat = %q", cfg.OutputFormat)
	}
	if !cfg.DryRun {
		t.Error("DryRun should be true")
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	yaml := `
source:
  host: "imap.example.com"
  username: "u"
  password: "p"
`
	f, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(yaml)
	f.Close()

	cfg, err := LoadConfig(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Source.Port != "993" {
		t.Errorf("default port = %q, want 993", cfg.Source.Port)
	}
	if cfg.OutputFormat != "eml" {
		t.Errorf("default output_format = %q, want eml", cfg.OutputFormat)
	}
}

func TestLoadConfigMissing(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadConfigMaildirSource(t *testing.T) {
	yaml := `
maildir_source:
  path: "/home/user/Maildir"
  domain: "example.com"
  user: "user"
output_dir: "/backup"
`
	f, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(yaml)
	f.Close()

	cfg, err := LoadConfig(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaildirSource == nil {
		t.Fatal("MaildirSource is nil")
	}
	if cfg.MaildirSource.Path != "/home/user/Maildir" {
		t.Errorf("Path = %q", cfg.MaildirSource.Path)
	}
	if cfg.MaildirSource.Domain != "example.com" {
		t.Errorf("Domain = %q", cfg.MaildirSource.Domain)
	}
}

func TestLoadConfigVirtualmin(t *testing.T) {
	yaml := `
virtualmin:
  mode: "ssh"
  domain: "example.com"
  ssh:
    host: "server.example.com"
    port: "22"
    username: "root"
    key_file: "/root/.ssh/id_rsa"
output_dir: "/backup"
output_format: "zip"
`
	f, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(yaml)
	f.Close()

	cfg, err := LoadConfig(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Virtualmin == nil {
		t.Fatal("Virtualmin is nil")
	}
	if cfg.Virtualmin.Mode != "ssh" {
		t.Errorf("Mode = %q", cfg.Virtualmin.Mode)
	}
	if cfg.Virtualmin.SSH == nil {
		t.Fatal("Virtualmin.SSH is nil")
	}
	if cfg.Virtualmin.SSH.Host != "server.example.com" {
		t.Errorf("SSH.Host = %q", cfg.Virtualmin.SSH.Host)
	}
}
