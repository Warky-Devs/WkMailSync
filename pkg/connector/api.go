package connector

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"

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
		log.Printf("[api] TLS certificate verification disabled")
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	base := fmt.Sprintf("%s://%s:%s/virtual-server/remote.cgi", scheme, apiCfg.Host, port)
	log.Printf("[api] Virtualmin API endpoint: %s", base)
	log.Printf("[api] Authenticating as: %s", apiCfg.Username)

	return &APIConnector{
		cfg:    cfg,
		client: &http.Client{Transport: transport},
		base:   base,
	}, nil
}

func (c *APIConnector) apiGet(program string, params map[string]string) (string, error) {
	apiCfg := c.cfg.API
	url := fmt.Sprintf("%s?program=%s&json=1", c.base, program)
	for k, v := range params {
		url += fmt.Sprintf("&%s=%s", k, v)
	}

	log.Printf("[api] GET %s", url)
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

	log.Printf("[api] Response: HTTP %d", resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	log.Printf("[api] Response body: %d bytes", len(body))
	return string(body), nil
}

func (c *APIConnector) ListDomains() ([]string, error) {
	log.Printf("[api] Listing domains")
	out, err := c.apiGet("list-domains", nil)
	if err != nil {
		return nil, err
	}
	all, err := parseVirtualminDomains([]byte(out))
	if err != nil {
		return nil, err
	}
	var domains []string
	for _, d := range all {
		if c.cfg.Domain != "" && d != c.cfg.Domain {
			log.Printf("[api] Skipping domain %s (filter: %s)", d, c.cfg.Domain)
			continue
		}
		log.Printf("[api] Found domain: %s", d)
		domains = append(domains, d)
	}
	log.Printf("[api] Total domains: %d", len(domains))
	return domains, nil
}

func (c *APIConnector) ListUsers(domain string) ([]MailUser, error) {
	log.Printf("[api] Listing users for domain: %s", domain)
	out, err := c.apiGet("list-users", map[string]string{"domain": domain})
	if err != nil {
		return nil, err
	}
	users, err := parseVirtualminUsersJSON(domain, []byte(out))
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		log.Printf("[api] Found user: %s  home: %s  maildir: %s", u.Username, u.HomeDir, u.MaildirPath)
	}
	log.Printf("[api] Total users in %s: %d", domain, len(users))
	return users, nil
}

func (c *APIConnector) Close() error { return nil }
