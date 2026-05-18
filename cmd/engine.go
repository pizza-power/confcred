package cmd

import (
	"context"
	"log/slog"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"

	"confcred/internal/confluence"
	"confcred/internal/findings"
	"confcred/internal/logging"
	"confcred/internal/parser"
	"confcred/internal/scanner"

	"golang.org/x/sync/semaphore"
)

func init() {
	debug.SetMemoryLimit(2 * 1024 * 1024 * 1024) // 2GB hard cap on Go heap
}

type ScanStats struct {
	PagesScanned      atomic.Int64
	AttachmentsParsed atomic.Int64
}

// scanPages reads lightweight page stubs from the channel. Each worker fetches
// the full page body on demand so only N workers (not the entire channel buffer)
// hold page HTML in memory at any time.
func scanPages(
	ctx context.Context,
	client *confluence.Client,
	pages <-chan confluence.PageStub,
	patterns []scanner.CompiledPattern,
	store *findings.Store,
	writer *findings.JSONLWriter,
	stats *ScanStats,
	workers int,
) {
	log := logging.Get()
	attachMem := semaphore.NewWeighted(flagMaxMemory)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case stub, ok := <-pages:
					if !ok {
						return
					}
					processPage(ctx, client, stub, patterns, store, writer, stats, log, workerID, attachMem)
				}
			}
		}(i)
	}

	wg.Wait()
}

func processPage(
	ctx context.Context,
	client *confluence.Client,
	stub confluence.PageStub,
	patterns []scanner.CompiledPattern,
	store *findings.Store,
	writer *findings.JSONLWriter,
	stats *ScanStats,
	log *slog.Logger,
	workerID int,
	attachMem *semaphore.Weighted,
) {
	stats.PagesScanned.Add(1)
	pageURL := client.BaseURL() + stub.WebUI

	log.Info("scanning page",
		"worker", workerID,
		"page_id", stub.ID,
		"title", stub.Title,
		"space", stub.SpaceKey,
	)

	loc := findings.Location{
		SpaceKey:  stub.SpaceKey,
		PageID:    stub.ID,
		PageTitle: stub.Title,
		PageURL:   pageURL,
		Source:    "body",
	}

	// Fetch the full page body on demand — only this worker holds it in memory.
	page, err := client.GetPage(ctx, stub.ID)
	if err != nil {
		if ctx.Err() == nil {
			log.Warn("fetch page body failed", "page_id", stub.ID, "error", err)
		}
		return
	}

	// Force-copy to break reference to the JSON decoder's backing array.
	bodyHTML := strings.Clone(page.Body.Storage.Value)
	page = nil

	bodyText := stripHTML(bodyHTML)
	inCodeBlock := strings.Contains(bodyHTML, "<ac:structured-macro ac:name=\"code\"") ||
		strings.Contains(bodyHTML, "<pre>") ||
		strings.Contains(bodyHTML, "<code>")

	// Done with raw HTML — release it.
	bodyHTML = ""

	matches := scanner.Scan(patterns, bodyText, inCodeBlock)
	for _, m := range matches {
		f := scanner.ToFinding(m, loc)
		if store.Add(f) {
			findings.PrintFinding(f)
			if writer != nil {
				if err := writer.Write(f); err != nil {
					log.Error("write finding", "error", err)
				}
			}
			log.Info("finding",
				"pattern", f.Pattern,
				"value", logging.MaskValue(f.Value),
				"severity", f.Severity,
				"confidence", f.Confidence,
				"page", f.Location.PageTitle,
				"url", f.Location.PageURL,
			)
		}
	}

	// Release body text before attachment scanning — no longer needed.
	bodyText = ""
	matches = nil

	if ctx.Err() != nil {
		return
	}

	scanAttachments(ctx, client, stub.ID, patterns, store, writer, stats, loc, log, attachMem)
}

func scanAttachments(
	ctx context.Context,
	client *confluence.Client,
	pageID string,
	patterns []scanner.CompiledPattern,
	store *findings.Store,
	writer *findings.JSONLWriter,
	stats *ScanStats,
	baseLoc findings.Location,
	log *slog.Logger,
	attachMem *semaphore.Weighted,
) {
	attachments, err := client.GetAttachments(ctx, pageID)
	if err != nil {
		log.Warn("list attachments failed", "page_id", pageID, "error", err)
		return
	}

	for _, att := range attachments {
		if ctx.Err() != nil {
			return
		}
		if !confluence.IsParseable(att.Title) {
			continue
		}

		fileSize := att.Extensions.FileSize
		if fileSize <= 0 {
			fileSize = 1024 * 1024
		}
		if fileSize > flagMaxAttachSize {
			log.Debug("skipping large attachment",
				"file", att.Title,
				"size", fileSize,
				"max", flagMaxAttachSize,
			)
			continue
		}

		if err := attachMem.Acquire(ctx, fileSize); err != nil {
			return
		}

		data, err := client.DownloadAttachment(ctx, att.Links.Download, flagMaxAttachSize)
		if err != nil {
			attachMem.Release(fileSize)
			log.Warn("download attachment failed", "file", att.Title, "error", err)
			continue
		}

		var text string
		lower := strings.ToLower(att.Title)
		switch {
		case strings.HasSuffix(lower, ".docx"):
			text, err = parser.ExtractDOCX(data)
		case strings.HasSuffix(lower, ".pdf"):
			text, err = parser.ExtractPDF(data)
		}

		data = nil
		attachMem.Release(fileSize)

		if err != nil {
			log.Warn("parse attachment failed", "file", att.Title, "error", err)
			continue
		}

		stats.AttachmentsParsed.Add(1)

		loc := baseLoc
		loc.Source = "attachment"
		loc.Attachment = att.Title

		matches := scanner.Scan(patterns, text, false)
		for _, m := range matches {
			f := scanner.ToFinding(m, loc)
			if store.Add(f) {
				findings.PrintFinding(f)
				if writer != nil {
					if err := writer.Write(f); err != nil {
						log.Error("write finding", "error", err)
					}
				}
				log.Info("finding in attachment",
					"pattern", f.Pattern,
					"value", logging.MaskValue(f.Value),
					"severity", f.Severity,
					"file", att.Title,
					"page", baseLoc.PageTitle,
				)
			}
		}
	}
}

func stripHTML(s string) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
			b.WriteRune(' ')
		case !inTag:
			b.WriteRune(r)
		}
	}
	return b.String()
}
