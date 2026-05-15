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

// SearchCQL performs a CQL search and returns all matching pages, handling pagination.
func (c *Client) SearchCQL(ctx context.Context, cql string, limit int) ([]PageResult, error) {
	var all []PageResult
	start := 0
	pageSize := 25
	if limit > 0 && limit < pageSize {
		pageSize = limit
	}

	for {
		path := fmt.Sprintf("/rest/api/content/search?cql=%s&start=%d&limit=%d&expand=body.storage,space,version",
			url.QueryEscape(cql), start, pageSize)

		var result SearchResult
		if err := c.getJSON(ctx, path, &result); err != nil {
			return all, fmt.Errorf("search CQL (start=%d): %w", start, err)
		}

		all = append(all, result.Results...)
		c.log.Info("search page fetched", "returned", result.Size, "total_so_far", len(all))

		if result.Size < pageSize || result.Links.Next == "" {
			break
		}
		if limit > 0 && len(all) >= limit {
			break
		}
		start += result.Size
	}

	return all, nil
}
