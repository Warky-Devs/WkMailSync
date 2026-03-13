package connector

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
)

type LocalConnector struct {
	cfg *config.VirtualminConfig
}

func NewLocalConnector(cfg *config.VirtualminConfig) *LocalConnector {
	return &LocalConnector{cfg: cfg}
}

func (c *LocalConnector) ListDomains() ([]string, error) {
	log.Printf("[local] Running: virtualmin list-domains --json")
	out, err := exec.Command("virtualmin", "list-domains", "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("virtualmin list-domains failed: %v", err)
	}
	all, err := parseVirtualminDomains(out)
	if err != nil {
		return nil, err
	}
	var domains []string
	for _, d := range all {
		if c.cfg.Domain != "" && d != c.cfg.Domain {
			log.Printf("[local] Skipping domain %s (filter: %s)", d, c.cfg.Domain)
			continue
		}
		log.Printf("[local] Found domain: %s", d)
		domains = append(domains, d)
	}
	log.Printf("[local] Total domains: %d", len(domains))
	return domains, nil
}

func (c *LocalConnector) ListUsers(domain string) ([]MailUser, error) {
	log.Printf("[local] Running: virtualmin list-users --domain %s --json", domain)
	out, err := exec.Command("virtualmin", "list-users", "--domain", domain, "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("virtualmin list-users failed: %v", err)
	}
	users, err := parseVirtualminUsersJSON(domain, out)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		log.Printf("[local] Found user: %s  home: %s  maildir: %s", u.Username, u.HomeDir, u.MaildirPath)
	}
	log.Printf("[local] Total users in %s: %d", domain, len(users))
	return users, nil
}

func (c *LocalConnector) maildirBase() string {
	if c.cfg.MaildirBase != "" {
		return c.cfg.MaildirBase
	}
	return "/home/%s/homes/%s/Maildir"
}

func (c *LocalConnector) Close() error { return nil }

// virtualminResponse is the top-level JSON structure returned by virtualmin --json commands.
type virtualminResponse struct {
	Status string `json:"status"`
	Data   []struct {
		Name   string                       `json:"name"`
		Values map[string][]string          `json:"values"`
	} `json:"data"`
}

func parseVirtualminDomains(raw []byte) ([]string, error) {
	var resp virtualminResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse virtualmin JSON: %v", err)
	}
	var domains []string
	for _, entry := range resp.Data {
		if entry.Name != "" {
			domains = append(domains, entry.Name)
		}
	}
	return domains, nil
}

func parseVirtualminUsersJSON(domain string, raw []byte) ([]MailUser, error) {
	var resp virtualminResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse virtualmin JSON: %v", err)
	}

	var users []MailUser
	for _, entry := range resp.Data {
		v := entry.Values
		username := first(v["user"])
		maildir := first(v["mail_location"])
		home := first(v["home_directory"])

		if username == "" || maildir == "" {
			log.Printf("[virtualmin] Skipping incomplete user entry: %s", entry.Name)
			continue
		}

		users = append(users, MailUser{
			Domain:      domain,
			Username:    username,
			HomeDir:     home,
			MaildirPath: maildir,
		})
	}
	return users, nil
}

// first returns the first element of a slice, or "" if empty.
func first(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}
