package connector

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
	"github.com/Warky-Devs/WkMailSync/pkg/source"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

type SSHConnector struct {
	cfg    *config.VirtualminConfig
	client *gossh.Client
	sftp   *sftp.Client
}

func NewSSHConnector(cfg *config.VirtualminConfig) (*SSHConnector, error) {
	sshCfg := cfg.SSH
	if sshCfg == nil {
		return nil, fmt.Errorf("SSH config required for ssh mode")
	}

	authMethods, err := buildSSHAuth(sshCfg)
	if err != nil {
		return nil, err
	}

	port := sshCfg.Port
	if port == "" {
		port = "22"
	}

	clientCfg := &gossh.ClientConfig{
		User:            sshCfg.Username,
		Auth:            authMethods,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}

	client, err := gossh.Dial("tcp", fmt.Sprintf("%s:%s", sshCfg.Host, port), clientCfg)
	if err != nil {
		return nil, fmt.Errorf("SSH dial failed: %v", err)
	}

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("SFTP init failed: %v", err)
	}

	return &SSHConnector{cfg: cfg, client: client, sftp: sftpClient}, nil
}

func buildSSHAuth(cfg *config.SSHConfig) ([]gossh.AuthMethod, error) {
	var methods []gossh.AuthMethod
	if cfg.KeyFile != "" {
		key, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file: %v", err)
		}
		signer, err := gossh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}
		methods = append(methods, gossh.PublicKeys(signer))
	}
	if cfg.Password != "" {
		methods = append(methods, gossh.Password(cfg.Password))
	}
	return methods, nil
}

func (c *SSHConnector) runCommand(cmd string) (string, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	out, err := session.Output(cmd)
	if err != nil {
		return "", fmt.Errorf("command %q failed: %v", cmd, err)
	}
	return string(out), nil
}

func (c *SSHConnector) ListDomains() ([]string, error) {
	out, err := c.runCommand("virtualmin list-domains --name-only")
	if err != nil {
		return nil, err
	}
	var domains []string
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
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

func (c *SSHConnector) ListUsers(domain string) ([]MailUser, error) {
	out, err := c.runCommand(fmt.Sprintf("virtualmin list-users --domain %s --multiline", domain))
	if err != nil {
		return nil, err
	}
	maildirBase := c.cfg.MaildirBase
	if maildirBase == "" {
		maildirBase = "/home/%s/homes/%s/Maildir"
	}
	return parseVirtualminUsers(domain, out, maildirBase), nil
}

func (c *SSHConnector) Close() error {
	if c.sftp != nil {
		c.sftp.Close()
	}
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

func (c *SSHConnector) NewMaildirSource(maildirPath string) *SSHMaildirSource {
	return NewSSHMaildirSource(c.sftp, maildirPath)
}

// SSHMaildirSource reads Maildir over SFTP
type SSHMaildirSource struct {
	sftp *sftp.Client
	path string
}

func NewSSHMaildirSource(sftpClient *sftp.Client, path string) *SSHMaildirSource {
	return &SSHMaildirSource{sftp: sftpClient, path: path}
}

func (ms *SSHMaildirSource) ListFolders() ([]source.Folder, error) {
	entries, err := ms.sftp.ReadDir(ms.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read remote maildir: %v", err)
	}

	folders := []source.Folder{{Name: "INBOX"}}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if folderName, ok := strings.CutPrefix(name, "."); ok {
			folderName = strings.ReplaceAll(folderName, ".", "/")
			folders = append(folders, source.Folder{Name: folderName})
		}
	}
	return folders, nil
}

func (ms *SSHMaildirSource) ListMessages(folder source.Folder) ([]source.Message, error) {
	var dirPath string
	if folder.Name == "INBOX" {
		dirPath = ms.path
	} else {
		maildirName := "." + strings.ReplaceAll(folder.Name, "/", ".")
		dirPath = ms.path + "/" + maildirName
	}

	var messages []source.Message
	for _, subdir := range []string{"cur", "new"} {
		subPath := dirPath + "/" + subdir
		entries, err := ms.sftp.ReadDir(subPath)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			key := entry.Name()
			filePath := subPath + "/" + key

			f, err := ms.sftp.Open(filePath)
			if err != nil {
				continue
			}
			content, err := io.ReadAll(f)
			f.Close()
			if err != nil {
				continue
			}

			date := parseDateFromMaildirKey(key)
			if date.IsZero() {
				date = entry.ModTime()
			}

			flags := parseMaildirFlags(key)

			messages = append(messages, source.Message{
				MessageID: fmt.Sprintf("<%s@maildir>", key),
				Date:      date,
				Flags:     flags,
				Content:   content,
			})
		}
	}
	return messages, nil
}

func (ms *SSHMaildirSource) Close() error { return nil }

func parseDateFromMaildirKey(key string) time.Time {
	parts := strings.SplitN(key, ".", 2)
	if len(parts) < 1 {
		return time.Time{}
	}
	var ts int64
	if _, err := fmt.Sscanf(parts[0], "%d", &ts); err != nil || ts <= 0 {
		return time.Time{}
	}
	return time.Unix(ts, 0)
}

func parseMaildirFlags(filename string) []string {
	_, flagStr, ok := strings.Cut(filename, ":2,")
	if !ok {
		return nil
	}
	var flags []string
	for _, ch := range flagStr {
		switch ch {
		case 'S':
			flags = append(flags, `\Seen`)
		case 'R':
			flags = append(flags, `\Answered`)
		case 'F':
			flags = append(flags, `\Flagged`)
		case 'D':
			flags = append(flags, `\Draft`)
		case 'T':
			flags = append(flags, `\Deleted`)
		}
	}
	return flags
}
