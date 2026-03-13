package connector

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
)

type APIConnector struct {
	cfg    *config.VirtualminConfig
	client *http.Client
	base   string
}

func NewAPIConnector(cfg *config.VirtualminConfig) (*APIConnector, error) {
	apiCfg := cfg.API
	if apiCfg == nil {
		return nil, fmt.Errorf("API config required for api mode")
	}

	port := apiCfg.Port
	if port == "" {
		port = "10000"
	}

	scheme := "http"
	if apiCfg.UseTLS {
		scheme = "https"
	}

	transport := &http.Transport{}
	if apiCfg.InsecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &APIConnector{
		cfg:    cfg,
		client: &http.Client{Transport: transport},
		base:   fmt.Sprintf("%s://%s:%s/virtual-server/remote.cgi", scheme, apiCfg.Host, port),
	}, nil
}

func (c *APIConnector) apiGet(program string, params map[string]string) (string, error) {
	apiCfg := c.cfg.API
	url := fmt.Sprintf("%s?program=%s&multiline=", c.base, program)
	for k, v := range params {
		url += fmt.Sprintf("&%s=%s", k, v)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(apiCfg.Username, apiCfg.Password)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("API request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (c *APIConnector) ListDomains() ([]string, error) {
	out, err := c.apiGet("list-domains", nil)
	if err != nil {
		return nil, err
	}

	var result []string
	if err2 := json.Unmarshal([]byte(out), &result); err2 == nil {
		if c.cfg.Domain != "" {
			var filtered []string
			for _, d := range result {
				if d == c.cfg.Domain {
					filtered = append(filtered, d)
				}
			}
			return filtered, nil
		}
		return result, nil
	}

	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, ":") {
			if strings.HasPrefix(line, "name:") {
				domain := strings.TrimSpace(strings.TrimPrefix(line, "name:"))
				if c.cfg.Domain == "" || domain == c.cfg.Domain {
					result = append(result, domain)
				}
			}
		}
	}
	return result, nil
}

func (c *APIConnector) ListUsers(domain string) ([]MailUser, error) {
	out, err := c.apiGet("list-users", map[string]string{"domain": domain})
	if err != nil {
		return nil, err
	}
	maildirBase := c.cfg.MaildirBase
	if maildirBase == "" {
		maildirBase = "/home/%s/homes/%s/Maildir"
	}
	return parseVirtualminUsers(domain, out, maildirBase), nil
}

func (c *APIConnector) Close() error { return nil }
