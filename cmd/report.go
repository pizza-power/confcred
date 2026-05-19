package cmd

import (
	"fmt"
	"time"

	"confcred/internal/findings"

	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Regenerate HTML report from an existing findings JSONL file",
	Long: `Reads a findings.jsonl file and generates (or regenerates) the HTML report.
No Confluence connection is needed — useful after manually editing the JSONL
to remove false positives.

Examples:
  confcred report
  confcred report --output findings.jsonl --report report.html`,
	// Override PersistentPreRunE to skip Confluence URL/auth validation.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
	RunE: runReport,
}

func init() {
	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	if flagOutput == "" {
		flagOutput = "findings.jsonl"
	}
	if flagReport == "" {
		flagReport = "report.html"
	}

	store := findings.NewStore(0)
	err := findings.WriteHTMLReport(flagReport, flagOutput, store, 0, 0, time.Duration(0))
	if err != nil {
		return fmt.Errorf("generate report: %w", err)
	}

	fmt.Printf("Report written to %s (from %s)\n", flagReport, flagOutput)
	return nil
}
