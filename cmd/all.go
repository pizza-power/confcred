package cmd

import (
	"context"
	"fmt"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"confcred/internal/confluence"
	"confcred/internal/findings"
	"confcred/internal/logging"
	"confcred/internal/scanner"

	"github.com/spf13/cobra"
)

var (
	flagTimeout    string
	flagExhaustive bool
	flagPatterns   string
)

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "Crawl all Confluence spaces and scan for credentials",
	Long: `Enumerates all accessible spaces (or those specified via --spaces/--exclude-spaces),
fetches every page, and runs the full credential pattern library against page bodies
and DOCX/PDF attachments.

Requires either --timeout or --exhaustive:
  confcred all --timeout 30m
  confcred all --timeout 2h --spaces DEV,OPS,INFRA
  confcred all --exhaustive`,
	RunE: runAll,
}

func init() {
	allCmd.Flags().StringVar(&flagTimeout, "timeout", "", "Max runtime duration (e.g. 30m, 2h)")
	allCmd.Flags().BoolVar(&flagExhaustive, "exhaustive", false, "Crawl without time limit")
	allCmd.Flags().StringVar(&flagPatterns, "patterns", "", "Path to custom patterns YAML file")
	rootCmd.AddCommand(allCmd)
}

func runAll(cmd *cobra.Command, args []string) error {
	if flagTimeout == "" && !flagExhaustive {
		return fmt.Errorf("either --timeout or --exhaustive is required")
	}

	log := logging.Get()
	defer logging.Close()

	start := time.Now()
	log.Info("starting full crawl scan", "exhaustive", flagExhaustive, "timeout", flagTimeout)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if flagTimeout != "" {
		dur, err := time.ParseDuration(flagTimeout)
		if err != nil {
			return fmt.Errorf("invalid timeout: %w", err)
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dur)
		defer cancel()
		log.Info("timeout set", "duration", dur.String())
	}

	client := newConfluenceClient()

	var patterns []scanner.CompiledPattern
	if flagPatterns != "" {
		var err error
		patterns, err = scanner.LoadPatternsFromFile(flagPatterns)
		if err != nil {
			return fmt.Errorf("load custom patterns: %w", err)
		}
		log.Info("loaded custom patterns", "count", len(patterns))
	} else {
		patterns = scanner.DefaultPatterns()
		log.Info("using default patterns", "count", len(patterns))
	}

	store := findings.NewStore()
	stats := &ScanStats{}

	writer, err := findings.NewJSONLWriter(flagOutput)
	if err != nil {
		return fmt.Errorf("create output writer: %w", err)
	}
	defer writer.Close()

	spaces, err := client.GetAllSpaces(ctx)
	if err != nil {
		return fmt.Errorf("enumerate spaces: %w", err)
	}

	includeSpaces := splitCSV(flagSpaces)
	excludeSpaces := splitCSV(flagExcludeSpaces)
	spaces = confluence.FilterSpaces(spaces, includeSpaces, excludeSpaces)

	log.Info("spaces to scan", "count", len(spaces))
	fmt.Printf("Scanning %d spaces...\n\n", len(spaces))

	pages := make(chan confluence.PageResult, 100)

	// Monitor for timeout/cancellation and notify the user.
	go func() {
		<-ctx.Done()
		if ctx.Err() == context.DeadlineExceeded {
			fmt.Printf("\n⏱ Timeout reached, shutting down gracefully...\n")
			log.Warn("timeout reached, stopping scan")
		} else {
			fmt.Printf("\nInterrupted, shutting down gracefully...\n")
			log.Warn("scan interrupted by signal")
		}
	}()

	var producerWg sync.WaitGroup
	producerWg.Add(1)
	go func() {
		defer producerWg.Done()
		defer close(pages)
		for _, space := range spaces {
			if ctx.Err() != nil {
				return
			}
			log.Info("crawling space", "space", space.Key, "name", space.Name)
			fmt.Printf("Crawling space: %s (%s)\n", space.Key, space.Name)
			if err := client.GetSpacePages(ctx, space.Key, pages); err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Error("crawl space failed", "space", space.Key, "error", err)
			}
		}
	}()

	scanPages(ctx, client, pages, patterns, store, writer, stats, flagWorkers)
	producerWg.Wait()

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

	log.Info("full crawl complete",
		"elapsed", elapsed.String(),
		"pages_scanned", stats.PagesScanned.Load(),
		"attachments_parsed", stats.AttachmentsParsed.Load(),
		"findings", store.Count(),
	)

	return nil
}
