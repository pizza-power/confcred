package confluence

import (
	"context"
	"fmt"
	"net/url"
)

type PageListResult struct {
	Results []PageResult `json:"results"`
	Start   int          `json:"start"`
	Limit   int          `json:"limit"`
	Size    int          `json:"size"`
	Links   struct {
		Next string `json:"next"`
	} `json:"_links"`
}

// GetPage fetches a single page by ID with body content expanded.
func (c *Client) GetPage(ctx context.Context, pageID string) (*PageResult, error) {
	path := fmt.Sprintf("/rest/api/content/%s?expand=body.storage,space,version", pageID)
	var page PageResult
	if err := c.getJSON(ctx, path, &page); err != nil {
		return nil, fmt.Errorf("get page %s: %w", pageID, err)
	}
	return &page, nil
}

// GetSpacePages paginates through all pages in a space, sending lightweight stubs to the channel.
// Bodies are NOT fetched here — workers fetch them on demand to control memory.
// remaining is how many more pages we're allowed to send (0 = unlimited). Returns pages sent.
func (c *Client) GetSpacePages(ctx context.Context, spaceKey string, pages chan<- PageStub, remaining int) (int, error) {
	start := 0
	pageSize := 25
	sent := 0

	for {
		select {
		case <-ctx.Done():
			return sent, ctx.Err()
		default:
		}

		cql := fmt.Sprintf(`space="%s" AND type=page`, spaceKey)
		path := fmt.Sprintf("/rest/api/content/search?cql=%s&start=%d&limit=%d&expand=space",
			url.QueryEscape(cql), start, pageSize)

		var result PageListResult
		if err := c.getJSON(ctx, path, &result); err != nil {
			return sent, fmt.Errorf("list pages in %s (start=%d): %w", spaceKey, start, err)
		}

		for _, p := range result.Results {
			select {
			case <-ctx.Done():
				return sent, ctx.Err()
			case pages <- p.ToStub():
				sent++
			}
			if remaining > 0 && sent >= remaining {
				return sent, nil
			}
		}

		c.log.Debug("space page batch", "space", spaceKey, "returned", result.Size, "start", start)

		if result.Size < pageSize || result.Links.Next == "" {
			break
		}
		start += result.Size
	}

	return sent, nil
}
