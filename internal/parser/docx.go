package parser

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

const maxExtractedBytes = 10 * 1024 * 1024 // 10MB cap on extracted text

// ExtractDOCX reads a DOCX file from memory and returns its plain text content.
// No temporary files are written to disk. Output is capped at 10MB.
func ExtractDOCX(data []byte) (string, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("open zip: %w", err)
	}

	var textParts []string
	totalLen := 0

	docFiles := []string{"word/document.xml", "word/header1.xml", "word/header2.xml", "word/footer1.xml", "word/footer2.xml"}
	for _, name := range docFiles {
		if totalLen > maxExtractedBytes {
			break
		}
		for _, f := range r.File {
			if f.Name == name {
				text, err := extractXMLText(f)
				if err != nil {
					continue
				}
				if text != "" {
					textParts = append(textParts, text)
					totalLen += len(text)
				}
			}
		}
	}

	if len(textParts) == 0 {
		return "", fmt.Errorf("no text content found in DOCX")
	}

	result := strings.Join(textParts, "\n")
	if len(result) > maxExtractedBytes {
		result = result[:maxExtractedBytes]
	}
	return result, nil
}

func extractXMLText(f *zip.File) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return "", err
	}

	return stripXMLTags(data), nil
}

func stripXMLTags(data []byte) string {
	var b strings.Builder
	decoder := xml.NewDecoder(bytes.NewReader(data))

	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text != "" {
				b.WriteString(text)
				b.WriteString(" ")
			}
		case xml.EndElement:
			if t.Name.Local == "p" || t.Name.Local == "br" {
				b.WriteString("\n")
			}
		}
	}

	return strings.TrimSpace(b.String())
}
