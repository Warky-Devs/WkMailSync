package monitor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// StateStore tracks the last-seen IMAP UID per folder (persisted to disk as
// JSON) and a set of filenames already written (built by scanning output_dir
// at startup). Both checks are used together to deduplicate messages across
// process restarts.
type StateStore struct {
	mu        sync.Mutex
	stateFile string
	outputDir string
	uids      map[string]uint32          // folder → last seen UID
	files     map[string]map[string]bool // sanitized-folder → filename set
}

func NewStateStore(stateFile, outputDir string) *StateStore {
	return &StateStore{
		stateFile: stateFile,
		outputDir: outputDir,
		uids:      make(map[string]uint32),
		files:     make(map[string]map[string]bool),
	}
}

// Load reads the UID map from disk and scans output_dir for existing .eml files.
func (s *StateStore) Load() error {
	data, err := os.ReadFile(s.stateFile)
	if err == nil {
		_ = json.Unmarshal(data, &s.uids)
	}

	entries, err := os.ReadDir(s.outputDir)
	if err != nil {
		return nil // output dir may not exist yet; that's fine
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(s.outputDir, entry.Name())
		fes, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		m := make(map[string]bool, len(fes))
		for _, f := range fes {
			if strings.HasSuffix(f.Name(), ".eml") {
				m[f.Name()] = true
			}
		}
		if len(m) > 0 {
			s.files[entry.Name()] = m
		}
	}
	return nil
}

func (s *StateStore) LastUID(folder string) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uids[folder]
}

// IsKnownFile returns true if filename already exists in the sanitized folder dir.
func (s *StateStore) IsKnownFile(sanitizedFolder, filename string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.files[sanitizedFolder]; ok {
		return m[filename]
	}
	return false
}

// Record marks a message as processed: updates in-memory sets and flushes UIDs to disk.
func (s *StateStore) Record(folder, sanitizedFolder, filename string, uid uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.files[sanitizedFolder] == nil {
		s.files[sanitizedFolder] = make(map[string]bool)
	}
	s.files[sanitizedFolder][filename] = true

	if uid > s.uids[folder] {
		s.uids[folder] = uid
	}
	return s.flush()
}

// SetBaseUID records the current mailbox max UID on first connect so that
// existing messages are not backfilled. Only sets if no state exists yet.
func (s *StateStore) SetBaseUID(folder string, uid uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uids[folder] == 0 {
		s.uids[folder] = uid
		return s.flush()
	}
	return nil
}

// flush writes the UID map atomically via a temp file + rename.
func (s *StateStore) flush() error {
	data, err := json.MarshalIndent(s.uids, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.stateFile), 0755); err != nil {
		return err
	}
	tmp := s.stateFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.stateFile)
}

var invalidFolderChars = regexp.MustCompile(`[<>:"/\\|?*\x00-\x1F]`)

func sanitizeFolderName(name string) string {
	s := invalidFolderChars.ReplaceAllString(name, "_")
	s = strings.ReplaceAll(s, " ", "_")
	if len(s) > 100 {
		s = s[:100]
	}
	return s
}
