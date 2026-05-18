package confluence

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"confcred/internal/logging"

	"golang.org/x/time/rate"
)

type AuthMode int

const (
	AuthPAT AuthMode = iota
	AuthBasic
)

type ClientConfig struct {
	BaseURL   string
	AuthMode  AuthMode
	Token     string // PAT
	User      string // basic auth
	Pass      string // basic auth
	RateLimit float64
	Timeout   time.Duration
	Insecure  bool
}

type Client struct {
	baseURL    string
	httpClient *http.Client
	authMode   AuthMode
	token      string
	user       string
	pass       string
	limiter    *rate.Limiter
	log        *slog.Logger
}

func NewClient(cfg ClientConfig) *Client {
	baseURL := strings.TrimRight(cfg.BaseURL, "/")
	rl := cfg.RateLimit
	if rl <= 0 {
		rl = 10
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
		authMode: cfg.AuthMode,
		token:    cfg.Token,
		user:     cfg.User,
		pass:     cfg.Pass,
		limiter:  rate.NewLimiter(rate.Limit(rl), int(rl)),
		log:      logging.Get(),
	}
}

func (c *Client) do(ctx context.Context, method, path string) (*http.Response, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}

	url := c.baseURL + path
	c.log.Debug("API request", "method", method, "url", url)

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	switch c.authMode {
	case AuthPAT:
		req.Header.Set("Authorization", "Bearer "+c.token)
	case AuthBasic:
		req.SetBasicAuth(c.user, c.pass)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		c.log.Warn("API error", "status", resp.StatusCode, "url", url, "body", string(body))
		return nil, fmt.Errorf("API %d: %s", resp.StatusCode, string(body))
	}

	return resp, nil
}

func (c *Client) getJSON(ctx context.Context, path string, target interface{}) error {
	resp, err := c.do(ctx, http.MethodGet, path)
	if err != nil {
		return err
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	return json.NewDecoder(resp.Body).Decode(target)
}

func (c *Client) getRaw(ctx context.Context, path string, maxBytes int64) ([]byte, string, error) {
	resp, err := c.do(ctx, http.MethodGet, path)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	// Hard-cap how much we read regardless of what the server sends.
	reader := io.LimitReader(resp.Body, maxBytes+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, "", fmt.Errorf("read body: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, "", fmt.Errorf("response body exceeds max size (%d bytes)", maxBytes)
	}
	return data, resp.Header.Get("Content-Type"), nil
}

func (c *Client) BaseURL() string {
	return c.baseURL
}
