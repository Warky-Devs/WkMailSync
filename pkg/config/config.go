package config

import (
	"fmt"
	"os"
	"time"

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
	Source        ServerConfig      `yaml:"source"`
	Dest          ServerConfig      `yaml:"destination"`
	OutputDir     string            `yaml:"output_dir"`
	DryRun        bool              `yaml:"dry_run"`
	Subdirectory  string            `yaml:"subdirectory"`
	DateFrom      string            `yaml:"date_from"`
	DateTo        string            `yaml:"date_to"`
	OutputFormat  string            `yaml:"output_format"`
	MaildirSource *MaildirConfig    `yaml:"maildir_source"`
	Virtualmin    *VirtualminConfig `yaml:"virtualmin"`
}

type MaildirConfig struct {
	Path   string `yaml:"path"`
	Domain string `yaml:"domain"`
	User   string `yaml:"user"`
}

type VirtualminConfig struct {
	Mode        string               `yaml:"mode"`
	Domain      string               `yaml:"domain"`
	MaildirBase string               `yaml:"maildir_base"`
	SSH         *SSHConfig           `yaml:"ssh"`
	API         *VirtualminAPIConfig `yaml:"api"`
}

type SSHConfig struct {
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	KeyFile  string `yaml:"key_file"`
}

type VirtualminAPIConfig struct {
	Host        string       `yaml:"host"`
	Port        string       `yaml:"port"`
	Username    string       `yaml:"username"`
	Password    string       `yaml:"password"`
	UseTLS      bool         `yaml:"use_tls"`
	InsecureTLS bool         `yaml:"insecure_tls"`
	SSH         *SSHConfig   `yaml:"ssh"`
	IMAP        ServerConfig `yaml:"imap"`
}

type SyncStats struct {
	TotalMailboxes  int
	TotalMessages   int
	CopiedMessages  int
	SkippedMessages int
	Errors          int
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
