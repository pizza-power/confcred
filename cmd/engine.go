package cmd

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"

	"confcred/internal/confluence"
	"confcred/internal/findings"
	"confcred/internal/logging"
	"confcred/internal/parser"
	"confcred/internal/scanner"
)

type ScanStats struct {
	PagesScanned      atomic.Int64
	AttachmentsParsed atomic.Int64
}

// scanPages reads pages from the channel and scans each one (body + attachments).
func scanPages(
	ctx context.Context,
	client *confluence.Client,
	pages <-chan confluence.PageResult,
	patterns []scanner.CompiledPattern,
	store *findings.Store,
	writer *findings.JSONLWriter,
	stats *ScanStats,
	workers int,
) {
	log := logging.Get()
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case page, ok := <-pages:
					if !ok {
						return
					}
					processPage(ctx, client, page, patterns, store, writer, stats, log, workerID)
				}
			}
		}(i)
	}

	wg.Wait()
}

func processPage(
	ctx context.Context,
	client *confluence.Client,
	page confluence.PageResult,
	patterns []scanner.CompiledPattern,
	store *findings.Store,
	writer *findings.JSONLWriter,
	stats *ScanStats,
	log *slog.Logger,
	workerID int,
) {
	stats.PagesScanned.Add(1)
	pageURL := client.BaseURL() + page.Links.WebUI

	log.Info("scanning page",
		"worker", workerID,
		"page_id", page.ID,
		"title", page.Title,
		"space", page.Space.Key,
	)

	loc := findings.Location{
		SpaceKey:  page.Space.Key,
		PageID:    page.ID,
		PageTitle: page.Title,
		PageURL:   pageURL,
		Source:    "body",
	}

	bodyText := stripHTML(page.Body.Storage.Value)
	inCodeBlock := strings.Contains(page.Body.Storage.Value, "<ac:structured-macro ac:name=\"code\"") ||
		strings.Contains(page.Body.Storage.Value, "<pre>") ||
		strings.Contains(page.Body.Storage.Value, "<code>")

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

	if ctx.Err() != nil {
		return
	}

	scanAttachments(ctx, client, page.ID, patterns, store, writer, stats, loc, log)
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
		if att.Extensions.FileSize > flagMaxAttachSize {
			log.Debug("skipping large attachment",
				"file", att.Title,
				"size", att.Extensions.FileSize,
				"max", flagMaxAttachSize,
			)
			continue
		}

		data, err := client.DownloadAttachment(ctx, att.Links.Download)
		if err != nil {
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

// stripHTML is a simple HTML tag stripper for Confluence storage format.
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
