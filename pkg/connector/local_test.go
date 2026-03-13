package connector

import (
	"testing"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
)

func TestParseVirtualminUsers_Basic(t *testing.T) {
	output := `
username: alice
  home: /home/example.com/homes/alice
username: bob
  home: /home/example.com/homes/bob
`
	users := parseVirtualminUsers("example.com", output, "/home/%s/homes/%s/Maildir")
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	if users[0].Username != "alice" {
		t.Errorf("user[0].Username = %q", users[0].Username)
	}
	if users[0].Domain != "example.com" {
		t.Errorf("user[0].Domain = %q", users[0].Domain)
	}
	if users[1].Username != "bob" {
		t.Errorf("user[1].Username = %q", users[1].Username)
	}
}

func TestParseVirtualminUsers_DefaultMaildirBase(t *testing.T) {
	output := `
username: alice
  home: /home/example.com/homes/alice
`
	// When using the default template, MaildirPath should use home + "/Maildir"
	users := parseVirtualminUsers("example.com", output, "/home/%s/homes/%s/Maildir")
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].MaildirPath != "/home/example.com/homes/alice/Maildir" {
		t.Errorf("MaildirPath = %q", users[0].MaildirPath)
	}
	if users[0].HomeDir != "/home/example.com/homes/alice" {
		t.Errorf("HomeDir = %q", users[0].HomeDir)
	}
}

func TestParseVirtualminUsers_CustomMaildirBase(t *testing.T) {
	output := `
username: alice
  home: /home/example.com/homes/alice
`
	users := parseVirtualminUsers("example.com", output, "/var/mail/%s/%s")
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].MaildirPath != "/var/mail/example.com/alice" {
		t.Errorf("MaildirPath = %q", users[0].MaildirPath)
	}
}

func TestParseVirtualminUsers_Empty(t *testing.T) {
	users := parseVirtualminUsers("example.com", "", "/home/%s/homes/%s/Maildir")
	if len(users) != 0 {
		t.Errorf("expected 0 users, got %d", len(users))
	}
}

func TestParseVirtualminUsers_NoHome(t *testing.T) {
	output := `username: alice`
	users := parseVirtualminUsers("example.com", output, "/home/%s/homes/%s/Maildir")
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	// MaildirPath set from template when no home: line
	if users[0].MaildirPath != "/home/example.com/homes/alice/Maildir" {
		t.Errorf("MaildirPath = %q", users[0].MaildirPath)
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
