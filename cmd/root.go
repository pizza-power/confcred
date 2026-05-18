package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"confcred/internal/confluence"
	"confcred/internal/logging"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

var (
	flagURL              string
	flagToken            string
	flagUser             string
	flagPass             string
	flagSpaces           string
	flagExcludeSpaces    string
	flagWorkers          int
	flagRateLimit        float64
	flagMaxAttachSize    int64
	flagMaxMemory        int64
	flagMaxPageSize      int64
	flagOutput           string
	flagLogFile          string
	flagReport           string
	flagMaxPages         int
	flagVerbose          bool
	flagInsecure         bool
)

var rootCmd = &cobra.Command{
	Use:   "confcred",
	Short: "Confluence credential scanner for penetration testing",
	Long: `confcred searches Confluence Server/Data Center for exposed credentials,
secrets, API keys, connection strings, and other sensitive data.

Two modes:
  search  - search for a specific term via CQL, then scan results
  all     - crawl all (or filtered) spaces with the built-in pattern library`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		_ = godotenv.Load()

		if flagURL == "" {
			flagURL = os.Getenv("CONFLUENCE_URL")
		}
		if flagToken == "" {
			flagToken = os.Getenv("CONFLUENCE_TOKEN")
		}
		if flagUser == "" {
			flagUser = os.Getenv("CONFLUENCE_USER")
		}
		if flagPass == "" {
			flagPass = os.Getenv("CONFLUENCE_PASS")
		}

		if flagURL == "" {
			return fmt.Errorf("confluence URL is required (--url or CONFLUENCE_URL in .env)")
		}
		if flagToken == "" && (flagUser == "" || flagPass == "") {
			return fmt.Errorf("authentication required: set --token (or CONFLUENCE_TOKEN) for PAT auth, or --user/--pass (or CONFLUENCE_USER/CONFLUENCE_PASS) for basic auth")
		}

		if err := logging.Init(flagLogFile, flagVerbose); err != nil {
			return fmt.Errorf("init logging: %w", err)
		}

		return nil
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagURL, "url", "", "Confluence base URL (overrides CONFLUENCE_URL env)")
	rootCmd.PersistentFlags().StringVar(&flagToken, "token", "", "Personal Access Token (overrides CONFLUENCE_TOKEN env)")
	rootCmd.PersistentFlags().StringVar(&flagUser, "user", "", "Basic auth username (overrides CONFLUENCE_USER env)")
	rootCmd.PersistentFlags().StringVar(&flagPass, "pass", "", "Basic auth password (overrides CONFLUENCE_PASS env)")
	rootCmd.PersistentFlags().StringVar(&flagSpaces, "spaces", "", "Comma-separated space keys to include")
	rootCmd.PersistentFlags().StringVar(&flagExcludeSpaces, "exclude-spaces", "", "Comma-separated space keys to exclude")
	rootCmd.PersistentFlags().IntVar(&flagWorkers, "workers", 5, "Number of concurrent page fetch workers")
	rootCmd.PersistentFlags().Float64Var(&flagRateLimit, "rate-limit", 10, "Max API requests per second")
	rootCmd.PersistentFlags().Int64Var(&flagMaxAttachSize, "max-attachment-size", 20*1024*1024, "Max attachment size in bytes to download (default 20MB)")
	rootCmd.PersistentFlags().Int64Var(&flagMaxMemory, "max-memory", 256*1024*1024, "Max memory for in-flight attachment processing across all workers (default 256MB)")
	rootCmd.PersistentFlags().Int64Var(&flagMaxPageSize, "max-page-size", 50*1024*1024, "Max page body response size in bytes (default 50MB)")
	rootCmd.PersistentFlags().StringVar(&flagOutput, "output", "findings.jsonl", "Output file path for JSONL findings")
	rootCmd.PersistentFlags().StringVar(&flagLogFile, "log-file", "confcred.log", "Log file path")
	rootCmd.PersistentFlags().StringVar(&flagReport, "report", "report.html", "HTML report output path")
	rootCmd.PersistentFlags().IntVar(&flagMaxPages, "max-pages", 10000, "Max pages to process (0 = unlimited)")
	rootCmd.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "Enable debug-level logging")
	rootCmd.PersistentFlags().BoolVar(&flagInsecure, "insecure", false, "Skip TLS certificate verification")
}

func newConfluenceClient() *confluence.Client {
	cfg := confluence.ClientConfig{
		BaseURL:     flagURL,
		RateLimit:   flagRateLimit,
		Timeout:     30 * time.Second,
		Insecure:    flagInsecure,
		MaxPageBody: flagMaxPageSize,
	}
	if flagToken != "" {
		cfg.AuthMode = confluence.AuthPAT
		cfg.Token = flagToken
	} else {
		cfg.AuthMode = confluence.AuthBasic
		cfg.User = flagUser
		cfg.Pass = flagPass
	}
	return confluence.NewClient(cfg)
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
