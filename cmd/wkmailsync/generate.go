package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
	"gopkg.in/yaml.v3"
)

func generateExampleConfig(mode string) {
	var cfg config.Config

	switch mode {
	case "imap":
		cfg = config.Config{
			Source: config.ServerConfig{
				Host:     "source.mail.example.com",
				Port:     "993",
				Username: "user@example.com",
				Password: "secret",
				UseTLS:   true,
			},
			Dest: config.ServerConfig{
				Host:     "dest.mail.example.com",
				Port:     "993",
				Username: "user@example.com",
				Password: "secret",
				UseTLS:   true,
			},
			OutputFormat:  "eml",
			DryRun:        false,
			DateFrom:      "2024-01-01",
			DateTo:        "2024-12-31",
			FolderExclude: []string{"Spam", "Trash"},
		}

	case "maildir":
		cfg = config.Config{
			MaildirSource: &config.MaildirConfig{
				Path: "/var/mail/vhosts/example.com/user/Maildir",
			},
			OutputDir:     "/backup/mail/user",
			OutputFormat:  "zip",
			DateFrom:      "2024-01-01",
			DateTo:        "2024-12-31",
			FolderExclude: []string{"Spam", "Trash"},
		}

	case "virtualmin":
		cfg = config.Config{
			Virtualmin: &config.VirtualminConfig{
				Mode:    "ssh",
				Workers: 4,
				SSH: &config.SSHConfig{
					Host:     "vps.example.com",
					Port:     "22",
					Username: "root",
					KeyFile:  "/home/user/.ssh/id_rsa",
				},
				API: &config.VirtualminAPIConfig{
					Host:     "vps.example.com",
					Port:     "10000",
					Username: "root",
					Password: "secret",
					UseTLS:   true,
				},
			},
			OutputDir:    "/backup/virtualmin",
			OutputFormat: "zip",
			DateFrom:     "2024-01-01",
			DateTo:       "2024-12-31",
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown config type %q. Choose: imap, maildir, virtualmin\n", mode)
		os.Exit(1)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate config: %v\n", err)
		os.Exit(1)
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get working directory: %v\n", err)
		os.Exit(1)
	}

	outPath := filepath.Join(cwd, "config.example.yaml")
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Example config written to: %s\n", outPath)
}
