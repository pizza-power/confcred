package scanner

import (
	"math"
	"strings"
)

const (
	// Matches with entropy below this are likely placeholders/english words.
	minEntropy = 3.0
	// Confidence penalty for low-entropy matches (not dropped, just demoted).
	lowEntropyPenalty = 40
	// Confidence penalty when placeholder words are detected in the value.
	placeholderPenalty = 50
	// Confidence penalty when surrounding context suggests documentation/examples.
	contextExamplePenalty = 30
)

// placeholderWords commonly appear in documentation examples instead of real secrets.
var placeholderWords = []string{
	"your-", "your_", "yourtokenhere", "your-token", "your_token",
	"example", "sample", "placeholder", "replace", "changeme",
	"insert", "todo", "fixme", "dummy", "fake", "test",
	"xxxxxxxx", "xxxx", "abcdef", "123456",
	"<token>", "{token}", "${token}", "{{token}}",
	"<key>", "{key}", "${key}", "{{key}}",
	"<secret>", "{secret}", "${secret}", "{{secret}}",
	"<password>", "{password}", "${password}",
	"my-token", "my_token", "my-key", "my_key",
	"token-here", "token_here", "key-here", "key_here",
	"api-key-here", "api_key_here",
	"put-your", "put_your", "enter-your", "enter_your",
}

// contextIndicators suggest the match is from documentation/examples, not live secrets.
var contextIndicators = []string{
	"example", "sample", "placeholder", "replace with",
	"replace this", "documentation", "tutorial",
	"for instance", "such as", "e.g.", "e.g,",
	"curl -h", "curl --header", "curl -x",
	"copy and paste", "shown below", "as follows",
	"# replace", "// replace", "<!-- replace",
	"todo:", "fixme:", "note:",
	"template", "mock", "stub",
}

// shannonEntropy calculates the Shannon entropy (bits per character) of a string.
// Higher entropy = more random = more likely to be a real secret.
// English text ≈ 3.5-4.5, random base64 ≈ 5.5-6.0, placeholders ≈ 2.5-3.5
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// extractSecretPart pulls out just the secret value from patterns that include
// a key= prefix. For "password=hunter2", returns "hunter2".
// For patterns without an assignment operator, returns the full value.
func extractSecretPart(value string) string {
	// Look for assignment patterns: key=value, key: value
	for _, sep := range []string{"= ", "=", ": ", ":"} {
		if idx := strings.Index(value, sep); idx >= 0 {
			after := strings.TrimSpace(value[idx+len(sep):])
			after = strings.Trim(after, `"'`)
			if len(after) > 0 {
				return after
			}
		}
	}
	// For "bearer XYZ" patterns
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "bearer ") {
		return strings.TrimSpace(value[7:])
	}
	return value
}

// containsPlaceholder checks if the value contains known placeholder words.
func containsPlaceholder(value string) bool {
	lower := strings.ToLower(value)
	for _, p := range placeholderWords {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// contextSuggestsExample checks if surrounding context indicates documentation.
func contextSuggestsExample(ctx string) bool {
	lower := strings.ToLower(ctx)
	for _, indicator := range contextIndicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}

// applyFilters adjusts confidence based on entropy, placeholder detection,
// and context analysis. Returns the adjusted confidence (may go to 0 or negative,
// which the caller should use to decide whether to keep the match).
func applyFilters(value, context string) int {
	penalty := 0

	secret := extractSecretPart(value)

	// Entropy check on the secret portion.
	if entropy := shannonEntropy(secret); entropy < minEntropy && len(secret) > 4 {
		penalty += lowEntropyPenalty
	}

	// Placeholder word check.
	if containsPlaceholder(value) {
		penalty += placeholderPenalty
	}

	// Context-based demotion.
	if contextSuggestsExample(context) {
		penalty += contextExamplePenalty
	}

	return penalty
}
