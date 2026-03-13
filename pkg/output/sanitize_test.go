package output

import (
	"strings"
	"testing"
)

func TestSanitizeFilename(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"hello world", "hello_world"},
		{"file<name>", "file_name_"},
		{`path/to\file`, "path_to_file"},
		{"normal", "normal"},
		{strings.Repeat("a", 120), strings.Repeat("a", 100)},
		{"Re: Meeting", "Re__Meeting"},
		{"file:name|check?", "file_name_check_"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := sanitizeFilename(tc.input)
			if got != tc.want {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestSanitizeFilenameMaxLength(t *testing.T) {
	long := strings.Repeat("x", 200)
	got := sanitizeFilename(long)
	if len(got) > 100 {
		t.Errorf("length %d exceeds 100", len(got))
	}
}
