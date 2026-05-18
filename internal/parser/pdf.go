package parser

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ledongthuc/pdf"
)

// ExtractPDF reads a PDF file from memory and returns its plain text content.
// No temporary files are written to disk. Output is capped at 10MB.
// Recovers from panics in the PDF library to prevent crashes on malformed files.
func ExtractPDF(data []byte) (result string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("pdf parser panic: %v", r)
		}
	}()

	reader := bytes.NewReader(data)
	pdfReader, err := pdf.NewReader(reader, int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("open pdf: %w", err)
	}

	numPages := pdfReader.NumPage()
	if numPages == 0 {
		return "", fmt.Errorf("pdf has no pages")
	}

	// Cap pages to avoid spending ages on huge PDFs.
	const maxPDFPages = 200
	if numPages > maxPDFPages {
		numPages = maxPDFPages
	}

	var b strings.Builder
	b.Grow(min(len(data), maxExtractedBytes))
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

		if b.Len() > maxExtractedBytes {
			break
		}
	}

	result = strings.TrimSpace(b.String())
	if result == "" {
		return "", fmt.Errorf("no extractable text in pdf")
	}
	if len(result) > maxExtractedBytes {
		result = result[:maxExtractedBytes]
	}
	return result, nil
}
