package scanner

import (
	"fmt"
	"os"
	"regexp"

	"confcred/internal/findings"

	"gopkg.in/yaml.v3"
)

type PatternDef struct {
	Name            string `yaml:"name"`
	Regex           string `yaml:"regex"`
	Severity        string `yaml:"severity"`
	ConfidenceBoost int    `yaml:"confidence_boost"`
}

type PatternFile struct {
	Patterns []PatternDef `yaml:"patterns"`
}

type CompiledPattern struct {
	Name            string
	Regex           *regexp.Regexp
	Severity        findings.Severity
	ConfidenceBoost int
}

func LoadPatternsFromFile(path string) ([]CompiledPattern, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read patterns file: %w", err)
	}
	return parsePatternsYAML(data)
}

func parsePatternsYAML(data []byte) ([]CompiledPattern, error) {
	var pf PatternFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse patterns YAML: %w", err)
	}
	return compilePatterns(pf.Patterns)
}

func compilePatterns(defs []PatternDef) ([]CompiledPattern, error) {
	compiled := make([]CompiledPattern, 0, len(defs))
	for _, d := range defs {
		re, err := regexp.Compile(d.Regex)
		if err != nil {
			return nil, fmt.Errorf("compile pattern %q: %w", d.Name, err)
		}
		compiled = append(compiled, CompiledPattern{
			Name:            d.Name,
			Regex:           re,
			Severity:        parseSeverity(d.Severity),
			ConfidenceBoost: d.ConfidenceBoost,
		})
	}
	return compiled, nil
}

func parseSeverity(s string) findings.Severity {
	switch s {
	case "critical":
		return findings.SeverityCritical
	case "high":
		return findings.SeverityHigh
	case "medium":
		return findings.SeverityMedium
	case "low":
		return findings.SeverityLow
	default:
		return findings.SeverityMedium
	}
}

func DefaultPatterns() []CompiledPattern {
	defs := []PatternDef{
		// Cloud provider keys
		{Name: "AWS Access Key", Regex: `(?:^|[^A-Za-z0-9/+=])(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?:[^A-Za-z0-9/+=]|$)`, Severity: "critical", ConfidenceBoost: 30},
		{Name: "AWS Secret Key", Regex: `(?i)(?:aws_secret_access_key|aws_secret)\s*[:=]\s*[A-Za-z0-9/+=]{40}`, Severity: "critical", ConfidenceBoost: 30},
		{Name: "GCP Service Account", Regex: `"type"\s*:\s*"service_account"`, Severity: "critical", ConfidenceBoost: 25},
		{Name: "Azure Client Secret", Regex: `(?i)(?:azure[_-]?client[_-]?secret|AZURE_CLIENT_SECRET)\s*[:=]\s*\S{20,}`, Severity: "critical", ConfidenceBoost: 20},

		// Private keys
		{Name: "RSA Private Key", Regex: `-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----`, Severity: "critical", ConfidenceBoost: 40},
		{Name: "EC Private Key", Regex: `-----BEGIN\sEC\sPRIVATE\sKEY-----`, Severity: "critical", ConfidenceBoost: 40},
		{Name: "OpenSSH Private Key", Regex: `-----BEGIN\sOPENSSH\sPRIVATE\sKEY-----`, Severity: "critical", ConfidenceBoost: 40},
		{Name: "PGP Private Key", Regex: `-----BEGIN\sPGP\sPRIVATE\sKEY\sBLOCK-----`, Severity: "critical", ConfidenceBoost: 40},

		// Platform tokens
		{Name: "GitHub PAT", Regex: `ghp_[A-Za-z0-9]{36}`, Severity: "high", ConfidenceBoost: 30},
		{Name: "GitHub OAuth", Regex: `gho_[A-Za-z0-9]{36}`, Severity: "high", ConfidenceBoost: 30},
		{Name: "GitLab Token", Regex: `glpat-[A-Za-z0-9\-]{20,}`, Severity: "high", ConfidenceBoost: 30},
		{Name: "Slack Bot Token", Regex: `xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}`, Severity: "high", ConfidenceBoost: 25},
		{Name: "Slack User Token", Regex: `xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-f0-9]{32}`, Severity: "high", ConfidenceBoost: 25},
		{Name: "Slack Webhook", Regex: `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`, Severity: "high", ConfidenceBoost: 25},

		// Connection strings
		{Name: "JDBC Connection String", Regex: `jdbc:[a-z]+://[^\s"']+:[^\s"']+@[^\s"']+`, Severity: "critical", ConfidenceBoost: 20},
		{Name: "MongoDB URI", Regex: `mongodb(?:\+srv)?://[^\s"']+:[^\s"']+@[^\s"']+`, Severity: "critical", ConfidenceBoost: 25},
		{Name: "PostgreSQL URI", Regex: `postgres(?:ql)?://[^\s"']+:[^\s"']+@[^\s"']+`, Severity: "critical", ConfidenceBoost: 25},
		{Name: "MySQL URI", Regex: `mysql://[^\s"']+:[^\s"']+@[^\s"']+`, Severity: "critical", ConfidenceBoost: 25},
		{Name: "Redis URI", Regex: `redis(?:s)?://[^\s"']*:[^\s"']+@[^\s"']+`, Severity: "high", ConfidenceBoost: 20},
		{Name: "SMTP Credentials", Regex: `(?i)smtp://[^\s"']+:[^\s"']+@[^\s"']+`, Severity: "high", ConfidenceBoost: 20},

		// Generic secret patterns
		{Name: "Generic Password Assignment", Regex: `(?i)(?:password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{8,}["']?`, Severity: "medium", ConfidenceBoost: 0},
		{Name: "Generic Secret Assignment", Regex: `(?i)(?:secret|secret_key|secretkey)\s*[:=]\s*["']?[^\s"']{8,}["']?`, Severity: "medium", ConfidenceBoost: 0},
		{Name: "Generic API Key Assignment", Regex: `(?i)(?:api_key|apikey|api-key)\s*[:=]\s*["']?[^\s"']{16,}["']?`, Severity: "medium", ConfidenceBoost: 0},
		{Name: "Generic Token Assignment", Regex: `(?i)(?:token|auth_token|access_token)\s*[:=]\s*["']?[^\s"']{16,}["']?`, Severity: "medium", ConfidenceBoost: 0},
		{Name: "Bearer Token", Regex: `(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*`, Severity: "medium", ConfidenceBoost: 10},

		// Hashes (potential stored passwords)
		{Name: "Bcrypt Hash", Regex: `\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}`, Severity: "low", ConfidenceBoost: 10},

		// Other high-value
		{Name: "Heroku API Key", Regex: `(?i)heroku[_-]?api[_-]?key\s*[:=]\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, Severity: "high", ConfidenceBoost: 20},
		{Name: "SendGrid API Key", Regex: `SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}`, Severity: "high", ConfidenceBoost: 30},
		{Name: "Twilio API Key", Regex: `SK[0-9a-fA-F]{32}`, Severity: "high", ConfidenceBoost: 15},
		{Name: "Stripe Secret Key", Regex: `sk_live_[A-Za-z0-9]{24,}`, Severity: "critical", ConfidenceBoost: 35},
	}

	patterns, err := compilePatterns(defs)
	if err != nil {
		panic(fmt.Sprintf("BUG: default patterns failed to compile: %v", err))
	}
	return patterns
}
