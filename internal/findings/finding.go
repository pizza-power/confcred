package findings

import (
	"crypto/sha256"
	"fmt"
	"strings"
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
	sum := fmt.Sprintf("%x", h.Sum(nil))
	// Return a copy, not a substring, to avoid pinning the full hash string.
	id := make([]byte, 16)
	copy(id, sum[:16])
	return string(id)
}

const (
	MaxValueLen   = 200
	MaxContextLen = 300
	MaxSeenIDs    = 500000 // cap the dedup map to prevent unbounded growth
)

type Store struct {
	mu          sync.Mutex
	seen        map[string]struct{}
	findings    []Finding
	maxFindings int
	capped      bool
	seenCapped  bool
}

func NewStore(maxFindings int) *Store {
	if maxFindings <= 0 {
		maxFindings = 100000
	}
	return &Store{
		seen:        make(map[string]struct{}),
		findings:    make([]Finding, 0),
		maxFindings: maxFindings,
	}
}

// Add returns true if the finding was new and added, false if duplicate.
// Findings are truncated at ingestion to bound memory. After MaxFindings is
// reached, dedup still works but findings are no longer stored in memory
// (they should still be written to the JSONL file by the caller).
// Once the dedup map exceeds MaxSeenIDs, all new findings are treated as unique
// to prevent unbounded map growth.
func (s *Store) Add(f Finding) bool {
	if len(f.Value) > MaxValueLen {
		// strings.Clone ensures truncation doesn't pin the original.
		f.Value = strings.Clone(f.Value[:MaxValueLen]) + "..."
	}
	if len(f.Context) > MaxContextLen {
		f.Context = strings.Clone(f.Context[:MaxContextLen]) + "..."
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// If the dedup map is within bounds, check for duplicates.
	if len(s.seen) < MaxSeenIDs {
		if _, exists := s.seen[f.ID]; exists {
			return false
		}
		s.seen[f.ID] = struct{}{}
	} else if !s.seenCapped {
		s.seenCapped = true
	}

	if len(s.findings) < s.maxFindings {
		s.findings = append(s.findings, f)
	} else if !s.capped {
		s.capped = true
	}
	return true
}

// Capped returns true if the in-memory store hit its cap.
func (s *Store) Capped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.capped
}

func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

func (s *Store) StoredCount() int {
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
