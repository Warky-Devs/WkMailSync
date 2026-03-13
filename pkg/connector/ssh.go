package connector

import (
	"fmt"
	"io"
	"iter"
	"log"
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

	addr := fmt.Sprintf("%s:%s", sshCfg.Host, port)
	log.Printf("[ssh] Connecting to %s as %s", addr, sshCfg.Username)
	if sshCfg.KeyFile != "" {
		log.Printf("[ssh] Using key file: %s", sshCfg.KeyFile)
	} else {
		log.Printf("[ssh] Using password authentication")
	}

	clientCfg := &gossh.ClientConfig{
		User:            sshCfg.Username,
		Auth:            authMethods,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}

	client, err := gossh.Dial("tcp", addr, clientCfg)
	if err != nil {
		return nil, fmt.Errorf("SSH dial failed: %v", err)
	}
	log.Printf("[ssh] Connected to %s", addr)

	log.Printf("[ssh] Initialising SFTP subsystem")
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("SFTP init failed: %v", err)
	}
	log.Printf("[ssh] SFTP ready")

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
	log.Printf("[ssh] Executing: %s", cmd)
	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	out, err := session.Output(cmd)
	if err != nil {
		return "", fmt.Errorf("command %q failed: %v", cmd, err)
	}
	log.Printf("[ssh] Command output: %d bytes", len(out))
	return string(out), nil
}

func (c *SSHConnector) ListDomains() ([]string, error) {
	out, err := c.runCommand("virtualmin list-domains --json")
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
			log.Printf("[ssh] Skipping domain %s (filter: %s)", d, c.cfg.Domain)
			continue
		}
		log.Printf("[ssh] Found domain: %s", d)
		domains = append(domains, d)
	}
	log.Printf("[ssh] Total domains: %d", len(domains))
	return domains, nil
}

func (c *SSHConnector) ListUsers(domain string) ([]MailUser, error) {
	out, err := c.runCommand(fmt.Sprintf("virtualmin list-users --domain %s --json", domain))
	if err != nil {
		return nil, err
	}
	users, err := parseVirtualminUsersJSON(domain, []byte(out))
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		log.Printf("[ssh] Found user: %s  home: %s  maildir: %s", u.Username, u.HomeDir, u.MaildirPath)
	}
	log.Printf("[ssh] Total users in %s: %d", domain, len(users))
	return users, nil
}

func (c *SSHConnector) Close() error {
	log.Printf("[ssh] Closing connection")
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
	log.Printf("[sftp] Listing remote maildir: %s", ms.path)
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
			log.Printf("[sftp] Found folder: %s", folderName)
			folders = append(folders, source.Folder{Name: folderName})
		}
	}
	log.Printf("[sftp] Total folders: %d", len(folders))
	return folders, nil
}

func (ms *SSHMaildirSource) Messages(folder source.Folder) iter.Seq2[source.Message, error] {
	return func(yield func(source.Message, error) bool) {
		var dirPath string
		if folder.Name == "INBOX" {
			dirPath = ms.path
		} else {
			maildirName := "." + strings.ReplaceAll(folder.Name, "/", ".")
			dirPath = ms.path + "/" + maildirName
		}

		log.Printf("[sftp] Reading messages from %s (folder: %s)", dirPath, folder.Name)
		count := 0

		for _, subdir := range []string{"cur", "new"} {
			subPath := dirPath + "/" + subdir
			entries, err := ms.sftp.ReadDir(subPath)
			if err != nil {
				log.Printf("[sftp] Skipping %s: %v", subPath, err)
				continue
			}
			log.Printf("[sftp] %s: %d entries", subPath, len(entries))

			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				key := entry.Name()
				filePath := subPath + "/" + key

				log.Printf("[sftp] Downloading %s (%d bytes)", filePath, entry.Size())
				f, err := ms.sftp.Open(filePath)
				if err != nil {
					log.Printf("[sftp] Failed to open %s: %v", filePath, err)
					yield(source.Message{}, fmt.Errorf("open %s: %w", filePath, err))
					continue
				}
				content, err := io.ReadAll(f)
				f.Close()
				if err != nil {
					log.Printf("[sftp] Failed to read %s: %v", filePath, err)
					yield(source.Message{}, fmt.Errorf("read %s: %w", filePath, err))
					continue
				}

				date := parseDateFromMaildirKey(key)
				if date.IsZero() {
					date = entry.ModTime()
				}
				flags := parseMaildirFlags(key)
				log.Printf("[sftp] Message: key=%s  date=%s  flags=%v  size=%d",
					key, date.Format("2006-01-02 15:04:05"), flags, len(content))

				count++
				if !yield(source.Message{
					MessageID: fmt.Sprintf("<%s@maildir>", key),
					Date:      date,
					Flags:     flags,
					Content:   content,
				}, nil) {
					return
				}
			}
		}
		log.Printf("[sftp] Total messages streamed in %s: %d", folder.Name, count)
	}
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
