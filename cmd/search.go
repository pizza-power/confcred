package cmd

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"confcred/internal/confluence"
	"confcred/internal/findings"
	"confcred/internal/logging"
	"confcred/internal/scanner"

	"github.com/spf13/cobra"
)

var searchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search Confluence for a specific term and scan results for credentials",
	Long: `Performs a CQL text search for the given query, then scans every matched page
body and its attachments (DOCX, PDF) through the credential pattern library.

Examples:
  confcred search "password"
  confcred search "jdbc connection" --spaces DEV,OPS
  confcred search "aws_secret_access_key"`,
	Args: cobra.ExactArgs(1),
	RunE: runSearch,
}

func init() {
	rootCmd.AddCommand(searchCmd)
}

func runSearch(cmd *cobra.Command, args []string) error {
	query := args[0]
	log := logging.Get()
	defer logging.Close()

	start := time.Now()
	log.Info("starting search scan", "query", query)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	client := newConfluenceClient()
	patterns := scanner.DefaultPatterns()
	store := findings.NewStore()
	stats := &ScanStats{}

	writer, err := findings.NewJSONLWriter(flagOutput)
	if err != nil {
		return fmt.Errorf("create output writer: %w", err)
	}
	defer writer.Close()

	cql := fmt.Sprintf(`siteSearch ~ "%s"`, query)
	includeSpaces := splitCSV(flagSpaces)
	excludeSpaces := splitCSV(flagExcludeSpaces)
	if len(includeSpaces) > 0 {
		cql += fmt.Sprintf(` AND space in (%s)`, joinQuoted(includeSpaces))
	}
	if len(excludeSpaces) > 0 {
		cql += fmt.Sprintf(` AND space not in (%s)`, joinQuoted(excludeSpaces))
	}

	log.Info("executing CQL", "cql", cql)

	results, err := client.SearchCQL(ctx, cql, 0)
	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	log.Info("search returned pages", "count", len(results))
	fmt.Printf("Found %d pages matching query, scanning...\n\n", len(results))

	pages := make(chan confluence.PageResult, len(results))
	for _, r := range results {
		pages <- r
	}
	close(pages)

	scanPages(ctx, client, pages, patterns, store, writer, stats, flagWorkers)

	elapsed := time.Since(start)
	pagesCount := int(stats.PagesScanned.Load())
	attachCount := int(stats.AttachmentsParsed.Load())

	findings.PrintSummary(store, pagesCount, attachCount, elapsed)

	if flagReport != "" {
		if err := findings.WriteHTMLReport(flagReport, store, pagesCount, attachCount, elapsed); err != nil {
			log.Error("write HTML report", "error", err)
		} else {
			fmt.Printf("  Report written to %s\n", flagReport)
		}
	}

	log.Info("search scan complete",
		"elapsed", elapsed.String(),
		"pages_scanned", stats.PagesScanned.Load(),
		"attachments_parsed", stats.AttachmentsParsed.Load(),
		"findings", store.Count(),
	)

	return nil
}

func joinQuoted(keys []string) string {
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf(`"%s"`, k))
	}
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += ","
		}
		result += p
	}
	return result
}
