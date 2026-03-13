package output

import (
	"regexp"
	"strings"
)

func sanitizeFilename(input string) string {
	invalidChars := regexp.MustCompile(`[<>:"/\\|?*\x00-\x1F]`)
	sanitized := invalidChars.ReplaceAllString(input, "_")
	sanitized = strings.ReplaceAll(sanitized, " ", "_")
	if len(sanitized) > 100 {
		sanitized = sanitized[:100]
	}
	return sanitized
}
