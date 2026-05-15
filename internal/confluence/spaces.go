package confluence

import (
	"context"
	"fmt"
)

type SpaceListResult struct {
	Results []Space `json:"results"`
	Start   int     `json:"start"`
	Limit   int     `json:"limit"`
	Size    int     `json:"size"`
	Links   struct {
		Next string `json:"next"`
	} `json:"_links"`
}

type Space struct {
	ID   int    `json:"id"`
	Key  string `json:"key"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// GetAllSpaces enumerates all spaces visible to the authenticated user.
func (c *Client) GetAllSpaces(ctx context.Context) ([]Space, error) {
	var all []Space
	start := 0
	pageSize := 25

	for {
		path := fmt.Sprintf("/rest/api/space?start=%d&limit=%d", start, pageSize)
		var result SpaceListResult
		if err := c.getJSON(ctx, path, &result); err != nil {
			return all, fmt.Errorf("list spaces (start=%d): %w", start, err)
		}

		all = append(all, result.Results...)
		c.log.Debug("spaces batch", "returned", result.Size, "total_so_far", len(all))

		if result.Size < pageSize || result.Links.Next == "" {
			break
		}
		start += result.Size
	}

	return all, nil
}

// FilterSpaces returns only spaces whose keys match the include list (if non-empty)
// and do not appear in the exclude list.
func FilterSpaces(spaces []Space, include, exclude []string) []Space {
	includeSet := toSet(include)
	excludeSet := toSet(exclude)

	var filtered []Space
	for _, s := range spaces {
		if len(includeSet) > 0 {
			if _, ok := includeSet[s.Key]; !ok {
				continue
			}
		}
		if _, ok := excludeSet[s.Key]; ok {
			continue
		}
		filtered = append(filtered, s)
	}
	return filtered
}

func toSet(keys []string) map[string]struct{} {
	m := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		if k != "" {
			m[k] = struct{}{}
		}
	}
	return m
}
