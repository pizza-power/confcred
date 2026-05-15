package parser

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ledongthuc/pdf"
)

// ExtractPDF reads a PDF file from memory and returns its plain text content.
// No temporary files are written to disk.
func ExtractPDF(data []byte) (string, error) {
	reader := bytes.NewReader(data)
	pdfReader, err := pdf.NewReader(reader, int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("open pdf: %w", err)
	}

	numPages := pdfReader.NumPage()
	if numPages == 0 {
		return "", fmt.Errorf("pdf has no pages")
	}

	var b strings.Builder
	for i := 1; i <= numPages; i++ {
		page := pdfReader.Page(i)
		if page.V.IsNull() {
			continue
		}

		text, err := page.GetPlainText(nil)
		if err != nil {
			continue
		}
		b.WriteString(text)
		b.WriteString("\n")
	}

	result := strings.TrimSpace(b.String())
	if result == "" {
		return "", fmt.Errorf("no extractable text in pdf")
	}
	return result, nil
}
