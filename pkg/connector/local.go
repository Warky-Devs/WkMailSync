package connector

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
)

type LocalConnector struct {
	cfg *config.VirtualminConfig
}

func NewLocalConnector(cfg *config.VirtualminConfig) *LocalConnector {
	return &LocalConnector{cfg: cfg}
}

func (c *LocalConnector) ListDomains() ([]string, error) {
	out, err := exec.Command("virtualmin", "list-domains", "--name-only").Output()
	if err != nil {
		return nil, fmt.Errorf("virtualmin list-domains failed: %v", err)
	}
	var domains []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if c.cfg.Domain != "" && line != c.cfg.Domain {
			continue
		}
		domains = append(domains, line)
	}
	return domains, nil
}

func (c *LocalConnector) ListUsers(domain string) ([]MailUser, error) {
	out, err := exec.Command("virtualmin", "list-users", "--domain", domain, "--multiline").Output()
	if err != nil {
		return nil, fmt.Errorf("virtualmin list-users failed: %v", err)
	}

	return parseVirtualminUsers(domain, string(out), c.maildirBase()), nil
}

func (c *LocalConnector) maildirBase() string {
	if c.cfg.MaildirBase != "" {
		return c.cfg.MaildirBase
	}
	return "/home/%s/homes/%s/Maildir"
}

func (c *LocalConnector) Close() error { return nil }

func parseVirtualminUsers(domain, output, maildirBase string) []MailUser {
	var users []MailUser
	var current *MailUser

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "username:") {
			if current != nil {
				users = append(users, *current)
			}
			username := strings.TrimSpace(strings.TrimPrefix(line, "username:"))
			maildirPath := fmt.Sprintf(maildirBase, domain, username)
			current = &MailUser{
				Domain:      domain,
				Username:    username,
				MaildirPath: maildirPath,
			}
		} else if current != nil && strings.HasPrefix(line, "home:") {
			current.HomeDir = strings.TrimSpace(strings.TrimPrefix(line, "home:"))
			if maildirBase == "/home/%s/homes/%s/Maildir" {
				current.MaildirPath = current.HomeDir + "/Maildir"
			}
		}
	}
	if current != nil {
		users = append(users, *current)
	}
	return users
}
