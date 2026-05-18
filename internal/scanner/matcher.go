package scanner

import (
	"strings"
	"time"

	"confcred/internal/findings"
)

// clone breaks the substring reference so the original backing array can be GC'd.
func clone(s string) string { return strings.Clone(s) }

const contextRadius = 100

type MatchResult struct {
	Pattern    string
	Value      string
	Context    string
	Severity   findings.Severity
	Confidence int
}

const maxMatchesPerPattern = 50 // avoid regex explosion on noisy pages

// Scan runs all compiled patterns against the given text and returns matches.
// inCodeBlock boosts confidence when the match was found inside a code/preformatted context.
// All returned strings are cloned to avoid pinning the input text in memory.
// Matches are filtered for entropy, placeholder words, and documentation context.
func Scan(patterns []CompiledPattern, text string, inCodeBlock bool) []MatchResult {
	var results []MatchResult

	for _, p := range patterns {
		matches := p.Regex.FindAllStringIndex(text, maxMatchesPerPattern)
		for _, loc := range matches {
			value := strings.TrimSpace(text[loc[0]:loc[1]])
			if len(value) == 0 {
				continue
			}

			// Clone both value and context to prevent pinning the entire
			// input text (up to 5MB) via substring references.
			ctx := clone(extractContext(text, loc[0], loc[1]))
			confidence := baseConfidence(p.Severity) + p.ConfidenceBoost
			if inCodeBlock {
				confidence += 20
			}

			// Apply false-positive filters: entropy, placeholders, context.
			penalty := applyFilters(value, ctx)
			confidence -= penalty

			// Drop matches that fall below minimum confidence after filtering.
			if confidence <= 0 {
				continue
			}
			if confidence > 100 {
				confidence = 100
			}

			results = append(results, MatchResult{
				Pattern:    p.Name,
				Value:      clone(value),
				Context:    ctx,
				Severity:   p.Severity,
				Confidence: confidence,
			})
		}
	}

	return results
}

func baseConfidence(s findings.Severity) int {
	switch s {
	case findings.SeverityCritical:
		return 40
	case findings.SeverityHigh:
		return 30
	case findings.SeverityMedium:
		return 20
	case findings.SeverityLow:
		return 10
	default:
		return 20
	}
}

func extractContext(text string, start, end int) string {
	ctxStart := start - contextRadius
	if ctxStart < 0 {
		ctxStart = 0
	}
	ctxEnd := end + contextRadius
	if ctxEnd > len(text) {
		ctxEnd = len(text)
	}

	ctx := text[ctxStart:ctxEnd]
	ctx = strings.ReplaceAll(ctx, "\n", " ")
	ctx = strings.Join(strings.Fields(ctx), " ")
	return ctx
}

// ToFinding converts a MatchResult into a Finding with location info.
func ToFinding(mr MatchResult, loc findings.Location) findings.Finding {
	id := findings.GenerateID(mr.Pattern, mr.Value, loc.PageID, loc.Source, loc.Attachment)
	return findings.Finding{
		ID:         id,
		Pattern:    mr.Pattern,
		Value:      mr.Value,
		Context:    mr.Context,
		Location:   loc,
		Severity:   mr.Severity,
		Confidence: mr.Confidence,
		FoundAt:    time.Now(),
	}
}
