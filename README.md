# confcred

Confluence Server/Data Center credential scanner for internal penetration testing. Searches page bodies and DOCX/PDF attachments for secrets, API keys, connection strings, and other sensitive data.

## Setup

```
cp .env.example .env
# edit .env with your Confluence URL and PAT
```

Requires Go 1.21+.

## Build

```
go build -o confcred .
```

## Usage

**Search** — scan pages matching a query:

```
./confcred search "password"
./confcred search "jdbc connection" --spaces DEV,OPS
```

**All** — crawl all spaces with the built-in pattern library:

```
./confcred all --timeout 30m
./confcred all --exhaustive --spaces INFRA --exclude-spaces ARCHIVE
```

Findings are printed to the console and written to `findings.jsonl`. Logs go to `confcred.log`.

## Key flags

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | `.env` | Confluence base URL |
| `--token` | `.env` | Personal Access Token |
| `--workers` | 5 | Concurrent fetch workers |
| `--rate-limit` | 10 | Max requests/sec |
| `--max-attachment-size` | 50MB | Skip attachments above this |
| `--timeout` | — | Max runtime for `all` mode |
| `--exhaustive` | false | No time limit for `all` mode |
| `--patterns` | built-in | Custom patterns YAML path |
| `--output` | findings.jsonl | Findings output path |
| `--verbose` | false | Debug logging |
