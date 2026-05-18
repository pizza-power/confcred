package confluence

import (
	"context"
	"fmt"
	"net/url"
)

type SearchResult struct {
	Results []PageResult `json:"results"`
	Start   int          `json:"start"`
	Limit   int          `json:"limit"`
	Size    int          `json:"size"`
	Links   struct {
		Next string `json:"next"`
	} `json:"_links"`
}

type PageResult struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Title string `json:"title"`
	Space struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	} `json:"space"`
	Body struct {
		Storage struct {
			Value string `json:"value"`
		} `json:"storage"`
		View struct {
			Value string `json:"value"`
		} `json:"view"`
	} `json:"body"`
	Links struct {
		WebUI string `json:"webui"`
	} `json:"_links"`
}

// PageStub is a lightweight reference to a page without the body content.
// Used in channels to avoid holding large HTML bodies in memory while queued.
type PageStub struct {
	ID       string
	Title    string
	SpaceKey string
	WebUI    string
}

func (p PageResult) ToStub() PageStub {
	return PageStub{
		ID:       p.ID,
		Title:    p.Title,
		SpaceKey: p.Space.Key,
		WebUI:    p.Links.WebUI,
	}
}

// SearchCQL streams page stubs matching the CQL query into the provided channel.
// It paginates automatically and stops after maxPages stubs have been sent (0 = no limit).
func (c *Client) SearchCQL(ctx context.Context, cql string, maxPages int, pages chan<- PageStub) (int, error) {
	start := 0
	pageSize := 25
	sent := 0

	for {
		select {
		case <-ctx.Done():
			return sent, ctx.Err()
		default:
		}

		path := fmt.Sprintf("/rest/api/content/search?cql=%s&start=%d&limit=%d&expand=space",
			url.QueryEscape(cql), start, pageSize)

		var result SearchResult
		if err := c.getJSON(ctx, path, &result); err != nil {
			return sent, fmt.Errorf("search CQL (start=%d): %w", start, err)
		}

		for _, r := range result.Results {
			select {
			case <-ctx.Done():
				return sent, ctx.Err()
			case pages <- r.ToStub():
				sent++
			}
			if maxPages > 0 && sent >= maxPages {
				return sent, nil
			}
		}

		c.log.Info("search page fetched", "returned", result.Size, "total_so_far", sent)

		if result.Size < pageSize || result.Links.Next == "" {
			break
		}
		start += result.Size
	}

	return sent, nil
}
