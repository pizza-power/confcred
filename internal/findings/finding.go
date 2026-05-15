package findings

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

type Location struct {
	SpaceKey   string `json:"space_key"`
	PageID     string `json:"page_id"`
	PageTitle  string `json:"page_title"`
	PageURL    string `json:"page_url"`
	Source     string `json:"source"` // "body" or "attachment"
	Attachment string `json:"attachment,omitempty"`
}

type Finding struct {
	ID         string   `json:"id"`
	Pattern    string   `json:"pattern"`
	Value      string   `json:"value"`
	Context    string   `json:"context"`
	Location   Location `json:"location"`
	Severity   Severity `json:"severity"`
	Confidence int      `json:"confidence"`
	FoundAt    time.Time `json:"found_at"`
}

// GenerateID creates a deterministic dedup key from the pattern, value, page, and source.
func GenerateID(pattern, value, pageID, source, attachment string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s", pattern, value, pageID, source, attachment)
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

type Store struct {
	mu       sync.Mutex
	seen     map[string]struct{}
	findings []Finding
}

func NewStore() *Store {
	return &Store{
		seen:     make(map[string]struct{}),
		findings: make([]Finding, 0),
	}
}

// Add returns true if the finding was new and added, false if duplicate.
func (s *Store) Add(f Finding) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.seen[f.ID]; exists {
		return false
	}
	s.seen[f.ID] = struct{}{}
	s.findings = append(s.findings, f)
	return true
}

func (s *Store) All() []Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Finding, len(s.findings))
	copy(out, s.findings)
	return out
}

func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.findings)
}

func (s *Store) CountBySeverity() map[Severity]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts := make(map[Severity]int)
	for _, f := range s.findings {
		counts[f.Severity]++
	}
	return counts
}
