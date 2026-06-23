package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Host        string        `yaml:"host,omitempty"`
	Port        string        `yaml:"port,omitempty"`
	Username    string        `yaml:"username,omitempty"`
	Password    string        `yaml:"password,omitempty"`
	UseTLS      bool          `yaml:"use_tls,omitempty"`
	InsecureTLS bool          `yaml:"insecure_tls,omitempty"`
	OAuth2      *OAuth2Config `yaml:"oauth2,omitempty"`
}

type Config struct {
	Source        ServerConfig      `yaml:"source,omitempty"`
	Dest          ServerConfig      `yaml:"destination,omitempty"`
	OutputDir     string            `yaml:"output_dir,omitempty"`
	DryRun        bool              `yaml:"dry_run,omitempty"`
	Subdirectory  string            `yaml:"subdirectory,omitempty"`
	DateFrom      string            `yaml:"date_from,omitempty"`
	DateTo        string            `yaml:"date_to,omitempty"`
	OutputFormat  string            `yaml:"output_format,omitempty"`
	MaildirSource *MaildirConfig    `yaml:"maildir_source,omitempty"`
	Virtualmin    *VirtualminConfig `yaml:"virtualmin,omitempty"`
	Monitor       *MonitorConfig    `yaml:"monitor,omitempty"`
	FolderInclude []string          `yaml:"folder_include,omitempty"` // only sync these folders; empty = all
	FolderExclude []string          `yaml:"folder_exclude,omitempty"` // skip these folders
	StateFile     string            `yaml:"state_file,omitempty"`     // persists last-seen UID per folder; default: output_dir/.wksync_state.json
}

type OAuth2Config struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	RefreshToken string `yaml:"refresh_token"`
}

type MonitorServerConfig struct {
	Host        string        `yaml:"host"`
	Port        string        `yaml:"port,omitempty"`
	Username    string        `yaml:"username"`
	Password    string        `yaml:"password,omitempty"`
	UseTLS      bool          `yaml:"use_tls,omitempty"`
	InsecureTLS bool          `yaml:"insecure_tls,omitempty"`
	OAuth2      *OAuth2Config `yaml:"oauth2,omitempty"`
}

type WebhookConfig struct {
	Enabled     bool   `yaml:"enabled"`
	URL         string `yaml:"url"`
	IncludeBody *bool  `yaml:"include_body,omitempty"` // nil = true (default include)
	TimeoutSec  int    `yaml:"timeout_sec,omitempty"`
}

type MonitorConfig struct {
	Source         MonitorServerConfig `yaml:"source"`
	OutputDir      string              `yaml:"output_dir"`
	StateFile      string              `yaml:"state_file,omitempty"`
	FolderInclude  []string            `yaml:"folder_include,omitempty"`
	FolderExclude  []string            `yaml:"folder_exclude,omitempty"`
	Webhook        *WebhookConfig      `yaml:"webhook,omitempty"`
	MaxConnections int                 `yaml:"max_connections,omitempty"` // default 3
	IdleWindowSec  int                 `yaml:"idle_window_sec,omitempty"` // seconds per folder before rotating; default 30
}

type MaildirConfig struct {
	Path   string `yaml:"path,omitempty"`
	Domain string `yaml:"domain,omitempty"`
	User   string `yaml:"user,omitempty"`
}

type VirtualminConfig struct {
	Mode        string               `yaml:"mode,omitempty"`
	Domain      string               `yaml:"domain,omitempty"`
	MaildirBase string               `yaml:"maildir_base,omitempty"`
	Workers     int                  `yaml:"workers,omitempty"` // parallel domain workers; default 4
	SSH         *SSHConfig           `yaml:"ssh,omitempty"`
	API         *VirtualminAPIConfig `yaml:"api,omitempty"`
}

type SSHConfig struct {
	Host     string `yaml:"host,omitempty"`
	Port     string `yaml:"port,omitempty"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	KeyFile  string `yaml:"key_file,omitempty"`
}

type VirtualminAPIConfig struct {
	Host        string       `yaml:"host,omitempty"`
	Port        string       `yaml:"port,omitempty"`
	Username    string       `yaml:"username,omitempty"`
	Password    string       `yaml:"password,omitempty"`
	UseTLS      bool         `yaml:"use_tls,omitempty"`
	InsecureTLS bool         `yaml:"insecure_tls,omitempty"`
	SSH         *SSHConfig   `yaml:"ssh,omitempty"`
	IMAP        ServerConfig `yaml:"imap,omitempty"`
}

type SyncStats struct {
	TotalMailboxes  int
	TotalMessages   int
	CopiedMessages  int
	SkippedMessages int
	Errors          int
	BytesCopied     int64
	BytesTotal      int64
}

func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	if config.Source.Port == "" {
		config.Source.Port = "993"
	}
	if config.Dest.Port == "" {
		config.Dest.Port = "993"
	}
	if config.Monitor != nil {
		if config.Monitor.Source.Port == "" {
			config.Monitor.Source.Port = "993"
		}
		if config.Monitor.MaxConnections <= 0 {
			config.Monitor.MaxConnections = 3
		}
		if config.Monitor.IdleWindowSec <= 0 {
			config.Monitor.IdleWindowSec = 30
		}
	}
	if config.OutputFormat == "" {
		config.OutputFormat = "eml"
	}

	return &config, nil
}

func ParseDateString(dateStr string) (time.Time, error) {
	formats := []string{
		"2006-01-02",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05Z",
	}

	for _, format := range formats {
		if parsed, err := time.Parse(format, dateStr); err == nil {
			return parsed, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date %q", dateStr)
}
