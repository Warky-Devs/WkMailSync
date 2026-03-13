package sync

import (
	"errors"
	"iter"
	"testing"
	"time"

	"github.com/Warky-Devs/WkMailSync/pkg/source"
)

// --- fakes ---

type fakeSource struct {
	folders  []source.Folder
	messages map[string][]source.Message
	listErr  error
	msgErr   error
}

func (f *fakeSource) ListFolders() ([]source.Folder, error) {
	return f.folders, f.listErr
}

func (f *fakeSource) Messages(folder source.Folder) iter.Seq2[source.Message, error] {
	return func(yield func(source.Message, error) bool) {
		if f.msgErr != nil {
			yield(source.Message{}, f.msgErr)
			return
		}
		for _, msg := range f.messages[folder.Name] {
			if !yield(msg, nil) {
				return
			}
		}
	}
}

func (f *fakeSource) Close() error { return nil }

type fakeOutput struct {
	written  map[string][]byte // "folder/filename" -> content
	existing map[string]bool
	writeErr error
}

func newFakeOutput() *fakeOutput {
	return &fakeOutput{
		written:  make(map[string][]byte),
		existing: make(map[string]bool),
	}
}

func (o *fakeOutput) WriteMessage(folder, filename string, content []byte) error {
	if o.writeErr != nil {
		return o.writeErr
	}
	o.written[folder+"/"+filename] = content
	return nil
}

func (o *fakeOutput) Exists(key string) bool { return o.existing[key] }
func (o *fakeOutput) Close() error           { return nil }

// --- helpers ---

func msgAt(t time.Time) source.Message {
	return source.Message{
		MessageID: "<test@example.com>",
		Subject:   "Test Subject",
		From:      "sender",
		Date:      t,
		Content:   []byte("raw eml"),
	}
}

// --- tests ---

func TestSyncEngine_BasicCopy(t *testing.T) {
	src := &fakeSource{
		folders: []source.Folder{{Name: "INBOX"}},
		messages: map[string][]source.Message{
			"INBOX": {msgAt(time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC))},
		},
	}
	out := newFakeOutput()

	engine := NewSyncEngine(src, out)
	if err := engine.Run(); err != nil {
		t.Fatal(err)
	}

	if engine.Stats.CopiedMessages != 1 {
		t.Errorf("CopiedMessages = %d, want 1", engine.Stats.CopiedMessages)
	}
	if engine.Stats.TotalMessages != 1 {
		t.Errorf("TotalMessages = %d, want 1", engine.Stats.TotalMessages)
	}
	if len(out.written) != 1 {
		t.Errorf("written count = %d, want 1", len(out.written))
	}
}

func TestSyncEngine_Deduplication(t *testing.T) {
	msg := msgAt(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	filename := (&SyncEngine{}).buildFilename(msg)

	src := &fakeSource{
		folders:  []source.Folder{{Name: "INBOX"}},
		messages: map[string][]source.Message{"INBOX": {msg}},
	}
	out := newFakeOutput()
	out.existing[filename] = true

	engine := NewSyncEngine(src, out)
	engine.Run()

	if engine.Stats.CopiedMessages != 0 {
		t.Errorf("expected 0 copies, got %d", engine.Stats.CopiedMessages)
	}
	if engine.Stats.SkippedMessages != 1 {
		t.Errorf("expected 1 skip, got %d", engine.Stats.SkippedMessages)
	}
}

func TestSyncEngine_DryRun(t *testing.T) {
	src := &fakeSource{
		folders:  []source.Folder{{Name: "INBOX"}},
		messages: map[string][]source.Message{"INBOX": {msgAt(time.Now())}},
	}
	out := newFakeOutput()

	engine := NewSyncEngine(src, out)
	engine.DryRun = true
	engine.Run()

	if len(out.written) != 0 {
		t.Error("DryRun should not write any messages")
	}
	if engine.Stats.CopiedMessages != 1 {
		t.Errorf("DryRun CopiedMessages = %d, want 1", engine.Stats.CopiedMessages)
	}
}

func TestSyncEngine_DateFrom(t *testing.T) {
	cutoff := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	src := &fakeSource{
		folders: []source.Folder{{Name: "INBOX"}},
		messages: map[string][]source.Message{
			"INBOX": {
				msgAt(time.Date(2024, 5, 31, 0, 0, 0, 0, time.UTC)), // before
				msgAt(time.Date(2024, 6, 2, 0, 0, 0, 0, time.UTC)),  // after
			},
		},
	}
	out := newFakeOutput()

	engine := NewSyncEngine(src, out)
	engine.DateFrom = cutoff
	engine.Run()

	if engine.Stats.CopiedMessages != 1 {
		t.Errorf("CopiedMessages = %d, want 1", engine.Stats.CopiedMessages)
	}
	if engine.Stats.SkippedMessages != 1 {
		t.Errorf("SkippedMessages = %d, want 1", engine.Stats.SkippedMessages)
	}
}

func TestSyncEngine_DateTo(t *testing.T) {
	cutoff := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	src := &fakeSource{
		folders: []source.Folder{{Name: "INBOX"}},
		messages: map[string][]source.Message{
			"INBOX": {
				msgAt(time.Date(2024, 5, 31, 0, 0, 0, 0, time.UTC)), // before
				msgAt(time.Date(2024, 6, 2, 0, 0, 0, 0, time.UTC)),  // after
			},
		},
	}
	out := newFakeOutput()

	engine := NewSyncEngine(src, out)
	engine.DateTo = cutoff
	engine.Run()

	if engine.Stats.CopiedMessages != 1 {
		t.Errorf("CopiedMessages = %d, want 1", engine.Stats.CopiedMessages)
	}
}

func TestSyncEngine_DateRange(t *testing.T) {
	from := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2024, 9, 30, 0, 0, 0, 0, time.UTC)
	src := &fakeSource{
		folders: []source.Folder{{Name: "INBOX"}},
		messages: map[string][]source.Message{
			"INBOX": {
				msgAt(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),  // out
				msgAt(time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)), // in
				msgAt(time.Date(2024, 11, 1, 0, 0, 0, 0, time.UTC)), // out
			},
		},
	}
	out := newFakeOutput()

	engine := NewSyncEngine(src, out)
	engine.DateFrom = from
	engine.DateTo = to
	engine.Run()

	if engine.Stats.CopiedMessages != 1 {
		t.Errorf("CopiedMessages = %d, want 1", engine.Stats.CopiedMessages)
	}
	if engine.Stats.SkippedMessages != 2 {
		t.Errorf("SkippedMessages = %d, want 2", engine.Stats.SkippedMessages)
	}
}

func TestSyncEngine_NoDateSkipsZeroDate(t *testing.T) {
	// With date filter active, messages with zero date should be skipped
	src := &fakeSource{
		folders: []source.Folder{{Name: "INBOX"}},
		messages: map[string][]source.Message{
			"INBOX": {{MessageID: "<x>", Content: []byte("x")}}, // zero Date
		},
	}
	out := newFakeOutput()

	engine := NewSyncEngine(src, out)
	engine.DateFrom = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	engine.Run()

	if engine.Stats.SkippedMessages != 1 {
		t.Errorf("SkippedMessages = %d, want 1", engine.Stats.SkippedMessages)
	}
}

func TestSyncEngine_MultipleFolders(t *testing.T) {
	src := &fakeSource{
		folders: []source.Folder{{Name: "INBOX"}, {Name: "Sent"}, {Name: "Trash"}},
		messages: map[string][]source.Message{
			"INBOX": {msgAt(time.Now()), msgAt(time.Now())},
			"Sent":  {msgAt(time.Now())},
			"Trash": {},
		},
	}
	out := newFakeOutput()

	engine := NewSyncEngine(src, out)
	engine.Run()

	if engine.Stats.TotalMailboxes != 3 {
		t.Errorf("TotalMailboxes = %d, want 3", engine.Stats.TotalMailboxes)
	}
	if engine.Stats.CopiedMessages != 3 {
		t.Errorf("CopiedMessages = %d, want 3", engine.Stats.CopiedMessages)
	}
}

func TestSyncEngine_WriteError(t *testing.T) {
	src := &fakeSource{
		folders:  []source.Folder{{Name: "INBOX"}},
		messages: map[string][]source.Message{"INBOX": {msgAt(time.Now())}},
	}
	out := newFakeOutput()
	out.writeErr = errors.New("disk full")

	engine := NewSyncEngine(src, out)
	engine.Run()

	if engine.Stats.Errors != 1 {
		t.Errorf("Errors = %d, want 1", engine.Stats.Errors)
	}
	if engine.Stats.CopiedMessages != 0 {
		t.Errorf("CopiedMessages should be 0 on write error")
	}
}

func TestSyncEngine_ListFoldersError(t *testing.T) {
	src := &fakeSource{listErr: errors.New("connection lost")}
	out := newFakeOutput()

	engine := NewSyncEngine(src, out)
	err := engine.Run()
	if err == nil {
		t.Error("expected error from ListFolders failure")
	}
}

func TestSyncEngine_FolderExclude(t *testing.T) {
	src := &fakeSource{
		folders: []source.Folder{{Name: "INBOX"}, {Name: "Trash"}, {Name: "Spam"}},
		messages: map[string][]source.Message{
			"INBOX": {msgAt(time.Now())},
			"Trash": {msgAt(time.Now())},
			"Spam":  {msgAt(time.Now())},
		},
	}
	out := newFakeOutput()

	engine := NewSyncEngine(src, out)
	engine.FolderExclude = []string{"Trash", "Spam"}
	engine.Run()

	if engine.Stats.CopiedMessages != 1 {
		t.Errorf("CopiedMessages = %d, want 1 (only INBOX)", engine.Stats.CopiedMessages)
	}
}

func TestSyncEngine_FolderInclude(t *testing.T) {
	src := &fakeSource{
		folders: []source.Folder{{Name: "INBOX"}, {Name: "Sent"}, {Name: "Trash"}},
		messages: map[string][]source.Message{
			"INBOX": {msgAt(time.Now()), msgAt(time.Now())},
			"Sent":  {msgAt(time.Now())},
			"Trash": {msgAt(time.Now())},
		},
	}
	out := newFakeOutput()

	engine := NewSyncEngine(src, out)
	engine.FolderInclude = []string{"INBOX", "Sent"}
	engine.Run()

	if engine.Stats.CopiedMessages != 3 {
		t.Errorf("CopiedMessages = %d, want 3 (INBOX+Sent only)", engine.Stats.CopiedMessages)
	}
}

func TestSyncEngine_FolderIncludeCaseInsensitive(t *testing.T) {
	src := &fakeSource{
		folders:  []source.Folder{{Name: "INBOX"}, {Name: "Sent"}},
		messages: map[string][]source.Message{"INBOX": {msgAt(time.Now())}, "Sent": {msgAt(time.Now())}},
	}
	out := newFakeOutput()

	engine := NewSyncEngine(src, out)
	engine.FolderInclude = []string{"inbox"} // lowercase
	engine.Run()

	if engine.Stats.CopiedMessages != 1 {
		t.Errorf("CopiedMessages = %d, want 1", engine.Stats.CopiedMessages)
	}
}

func TestSyncEngine_FolderExcludeCaseInsensitive(t *testing.T) {
	src := &fakeSource{
		folders:  []source.Folder{{Name: "INBOX"}, {Name: "Trash"}},
		messages: map[string][]source.Message{"INBOX": {msgAt(time.Now())}, "Trash": {msgAt(time.Now())}},
	}
	out := newFakeOutput()

	engine := NewSyncEngine(src, out)
	engine.FolderExclude = []string{"trash"} // lowercase
	engine.Run()

	if engine.Stats.CopiedMessages != 1 {
		t.Errorf("CopiedMessages = %d, want 1 (Trash excluded)", engine.Stats.CopiedMessages)
	}
}

func TestSyncEngine_ListMessagesError(t *testing.T) {
	src := &fakeSource{
		folders: []source.Folder{{Name: "INBOX"}},
		msgErr:  errors.New("network error"),
	}
	out := newFakeOutput()

	engine := NewSyncEngine(src, out)
	engine.Run()

	if engine.Stats.Errors != 1 {
		t.Errorf("Errors = %d, want 1", engine.Stats.Errors)
	}
}

func TestBuildFilename(t *testing.T) {
	e := &SyncEngine{}
	msg := source.Message{
		Subject: "Hello World",
		From:    "John Doe",
		Date:    time.Date(2024, 1, 15, 9, 30, 0, 0, time.UTC),
	}
	got := e.buildFilename(msg)
	want := "20240115_093000_Hello_World_John_Doe.eml"
	if got != want {
		t.Errorf("buildFilename = %q, want %q", got, want)
	}
}

func TestBuildFilename_ZeroDate(t *testing.T) {
	e := &SyncEngine{}
	msg := source.Message{Subject: "Test", From: "x"}
	got := e.buildFilename(msg)
	if got == "" {
		t.Error("buildFilename should not return empty string for zero date")
	}
	if len(got) < 5 || got[len(got)-4:] != ".eml" {
		t.Errorf("expected .eml suffix, got %q", got)
	}
}

func TestSanitizeFilename(t *testing.T) {
	cases := []struct{ in, want string }{
		{"hello world", "hello_world"},
		{"file<bad>name", "file_bad_name"},
		{"normal", "normal"},
	}
	for _, tc := range cases {
		got := sanitizeFilename(tc.in)
		if got != tc.want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
