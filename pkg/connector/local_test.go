package connector

import (
	"encoding/json"
	"testing"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
)

// buildJSON constructs a virtualmin JSON response from a slice of user value maps.
func buildUsersJSON(domain string, users []map[string][]string) []byte {
	type entry struct {
		Name   string              `json:"name"`
		Values map[string][]string `json:"values"`
	}
	type resp struct {
		Status string  `json:"status"`
		Data   []entry `json:"data"`
	}
	r := resp{Status: "success"}
	for _, u := range users {
		name := ""
		if v, ok := u["email_address"]; ok && len(v) > 0 {
			name = v[0]
		}
		r.Data = append(r.Data, entry{Name: name, Values: u})
	}
	b, _ := json.Marshal(r)
	return b
}

func buildDomainsJSON(domains []string) []byte {
	type entry struct {
		Name   string              `json:"name"`
		Values map[string][]string `json:"values"`
	}
	type resp struct {
		Status string  `json:"status"`
		Data   []entry `json:"data"`
	}
	r := resp{Status: "success"}
	for _, d := range domains {
		r.Data = append(r.Data, entry{Name: d})
	}
	b, _ := json.Marshal(r)
	return b
}

func TestParseVirtualminDomains(t *testing.T) {
	raw := buildDomainsJSON([]string{"example.com", "test.org"})
	domains, err := parseVirtualminDomains(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}
	if domains[0] != "example.com" || domains[1] != "test.org" {
		t.Errorf("unexpected domains: %v", domains)
	}
}

func TestParseVirtualminDomains_Empty(t *testing.T) {
	raw := buildDomainsJSON(nil)
	domains, err := parseVirtualminDomains(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 0 {
		t.Errorf("expected 0, got %d", len(domains))
	}
}

func TestParseVirtualminUsersJSON_Basic(t *testing.T) {
	raw := buildUsersJSON("example.com", []map[string][]string{
		{
			"user":           {"alice"},
			"home_directory": {"/home/example/homes/alice"},
			"mail_location":  {"/home/example/homes/alice/Maildir"},
			"email_address":  {"alice@example.com"},
		},
		{
			"user":           {"bob"},
			"home_directory": {"/home/example/homes/bob"},
			"mail_location":  {"/home/example/homes/bob/Maildir"},
			"email_address":  {"bob@example.com"},
		},
	})

	users, err := parseVirtualminUsersJSON("example.com", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	if users[0].Username != "alice" {
		t.Errorf("user[0].Username = %q", users[0].Username)
	}
	if users[0].Domain != "example.com" {
		t.Errorf("user[0].Domain = %q", users[0].Domain)
	}
}

func TestParseVirtualminUsersJSON_MailLocationUsed(t *testing.T) {
	maildirPath := "/home/chroot/123/./home/example/homes/alice/Maildir"
	raw := buildUsersJSON("example.com", []map[string][]string{
		{
			"user":           {"alice"},
			"home_directory": {"/home/chroot/123/./home/example/homes/alice"},
			"mail_location":  {maildirPath},
			"email_address":  {"alice@example.com"},
		},
	})

	users, err := parseVirtualminUsersJSON("example.com", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].MaildirPath != maildirPath {
		t.Errorf("MaildirPath = %q, want %q", users[0].MaildirPath, maildirPath)
	}
}

func TestParseVirtualminUsersJSON_IncompleteDropped(t *testing.T) {
	// Missing mail_location and user — should be dropped
	raw := buildUsersJSON("example.com", []map[string][]string{
		{"home_directory": {"/home/example/homes/nobody"}},
	})
	users, err := parseVirtualminUsersJSON("example.com", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 0 {
		t.Errorf("expected 0 users (incomplete dropped), got %d", len(users))
	}
}

func TestParseVirtualminUsersJSON_InvalidJSON(t *testing.T) {
	_, err := parseVirtualminUsersJSON("example.com", []byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLocalConnector_MaildirBase_Default(t *testing.T) {
	c := NewLocalConnector(&config.VirtualminConfig{})
	if c.maildirBase() != "/home/%s/homes/%s/Maildir" {
		t.Errorf("unexpected default: %q", c.maildirBase())
	}
}

func TestLocalConnector_MaildirBase_Custom(t *testing.T) {
	c := NewLocalConnector(&config.VirtualminConfig{MaildirBase: "/custom/%s/%s"})
	if c.maildirBase() != "/custom/%s/%s" {
		t.Errorf("unexpected value: %q", c.maildirBase())
	}
}
