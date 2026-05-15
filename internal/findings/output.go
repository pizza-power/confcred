package findings

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"confcred/internal/logging"
)

type JSONLWriter struct {
	mu   sync.Mutex
	file *os.File
}

func NewJSONLWriter(path string) (*JSONLWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("open output file: %w", err)
	}
	return &JSONLWriter{file: f}, nil
}

func (w *JSONLWriter) Write(f Finding) error {
	masked := f
	masked.Value = logging.MaskValue(f.Value)

	data, err := json.Marshal(f)
	if err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	_, err = fmt.Fprintf(w.file, "%s\n", data)
	return err
}

func (w *JSONLWriter) Close() error {
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

func PrintFinding(f Finding) {
	sevColor := severityColor(f.Severity)
	fmt.Printf("%s[%s]%s %s | %s | %s | %s\n",
		sevColor,
		strings.ToUpper(string(f.Severity)),
		colorReset,
		f.Pattern,
		logging.MaskValue(f.Value),
		f.Location.PageTitle,
		f.Location.PageURL,
	)
	if f.Location.Source == "attachment" {
		fmt.Printf("         └─ attachment: %s\n", f.Location.Attachment)
	}
}

func PrintSummary(store *Store, pagesScanned, attachmentsParsed int, elapsed time.Duration) {
	counts := store.CountBySeverity()
	total := store.Count()

	fmt.Println()
	fmt.Println(strings.Repeat("─", 60))
	fmt.Println("  SCAN SUMMARY")
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("  Duration:           %s\n", elapsed.Round(time.Second))
	fmt.Printf("  Pages scanned:      %d\n", pagesScanned)
	fmt.Printf("  Attachments parsed: %d\n", attachmentsParsed)
	fmt.Printf("  Total findings:     %d\n", total)
	fmt.Println()
	if total > 0 {
		fmt.Printf("  %sCritical: %d%s\n", colorRed, counts[SeverityCritical], colorReset)
		fmt.Printf("  %sHigh:     %d%s\n", colorYellow, counts[SeverityHigh], colorReset)
		fmt.Printf("  %sMedium:   %d%s\n", colorCyan, counts[SeverityMedium], colorReset)
		fmt.Printf("  Low:      %d\n", counts[SeverityLow])
	}
	fmt.Println(strings.Repeat("─", 60))
}

const (
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorReset  = "\033[0m"
)

func severityColor(s Severity) string {
	switch s {
	case SeverityCritical:
		return colorRed
	case SeverityHigh:
		return colorYellow
	case SeverityMedium:
		return colorCyan
	default:
		return ""
	}
}
