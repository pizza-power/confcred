package parser

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"time"
)

// pdftoTextAvailable is set at init time to indicate whether the pdftotext
// binary (from poppler-utils) is installed and reachable on $PATH.
var pdftoTextAvailable bool

func init() {
	_, err := exec.LookPath("pdftotext")
	pdftoTextAvailable = err == nil
}

// PDFAvailable reports whether PDF extraction is supported on this system.
func PDFAvailable() bool {
	return pdftoTextAvailable
}

// ExtractPDF extracts plain text from a PDF by shelling out to pdftotext.
// The PDF data is piped to stdin; text is read from stdout.
// This keeps all PDF parsing memory in an isolated child process that is
// freed completely on exit — no Go heap impact regardless of PDF complexity.
func ExtractPDF(data []byte) (string, error) {
	if !pdftoTextAvailable {
		return "", fmt.Errorf("pdftotext not installed (apt install poppler-utils)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// pdftotext - - : read from stdin, write to stdout
	cmd := exec.CommandContext(ctx, "pdftotext", "-", "-")
	cmd.Stdin = bytes.NewReader(data)

	var stdout bytes.Buffer
	stdout.Grow(min(len(data), maxExtractedBytes))
	cmd.Stdout = &stdout

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("pdftotext failed: %w (stderr: %s)", err, stderr.String())
	}

	result := stdout.String()
	if len(result) > maxExtractedBytes {
		result = result[:maxExtractedBytes]
	}
	// Free the buffer immediately.
	stdout.Reset()

	if len(result) == 0 {
		return "", fmt.Errorf("no extractable text in pdf")
	}
	return result, nil
}

// ExtractPDFFromReader extracts text from a PDF read from the given reader.
// Useful if data is already streaming rather than in a byte slice.
func ExtractPDFFromReader(r io.Reader) (string, error) {
	if !pdftoTextAvailable {
		return "", fmt.Errorf("pdftotext not installed (apt install poppler-utils)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "pdftotext", "-", "-")
	cmd.Stdin = r

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("pdftotext failed: %w (stderr: %s)", err, stderr.String())
	}

	result := stdout.String()
	if len(result) > maxExtractedBytes {
		result = result[:maxExtractedBytes]
	}

	if len(result) == 0 {
		return "", fmt.Errorf("no extractable text in pdf")
	}
	return result, nil
}
