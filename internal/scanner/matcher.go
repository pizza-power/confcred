package scanner

import (
	"strings"
	"time"

	"confcred/internal/findings"
)

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
func Scan(patterns []CompiledPattern, text string, inCodeBlock bool) []MatchResult {
	var results []MatchResult

	for _, p := range patterns {
		matches := p.Regex.FindAllStringIndex(text, maxMatchesPerPattern)
		for _, loc := range matches {
			value := strings.TrimSpace(text[loc[0]:loc[1]])
			if len(value) == 0 {
				continue
			}

			ctx := extractContext(text, loc[0], loc[1])
			confidence := baseConfidence(p.Severity) + p.ConfidenceBoost
			if inCodeBlock {
				confidence += 20
			}
			if confidence > 100 {
				confidence = 100
			}

			results = append(results, MatchResult{
				Pattern:    p.Name,
				Value:      value,
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
