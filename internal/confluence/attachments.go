package confluence

import (
	"context"
	"fmt"
	"strings"
)

type AttachmentResult struct {
	Results []Attachment `json:"results"`
	Start   int          `json:"start"`
	Limit   int          `json:"limit"`
	Size    int          `json:"size"`
	Links   struct {
		Next string `json:"next"`
	} `json:"_links"`
}

type Attachment struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	MediaType string `json:"mediaType"`
	Links     struct {
		Download string `json:"download"`
	} `json:"_links"`
	Extensions struct {
		FileSize int64 `json:"fileSize"`
	} `json:"extensions"`
}

// GetAttachments lists all attachments for a given page.
func (c *Client) GetAttachments(ctx context.Context, pageID string) ([]Attachment, error) {
	var all []Attachment
	start := 0
	pageSize := 25

	for {
		path := fmt.Sprintf("/rest/api/content/%s/child/attachment?start=%d&limit=%d", pageID, start, pageSize)
		var result AttachmentResult
		if err := c.getJSON(ctx, path, &result); err != nil {
			return all, fmt.Errorf("list attachments for page %s: %w", pageID, err)
		}

		all = append(all, result.Results...)

		if result.Size < pageSize || result.Links.Next == "" {
			break
		}
		start += result.Size
	}

	return all, nil
}

// DownloadAttachment downloads the attachment content into memory.
func (c *Client) DownloadAttachment(ctx context.Context, downloadPath string) ([]byte, error) {
	data, _, err := c.getRaw(ctx, downloadPath)
	if err != nil {
		return nil, fmt.Errorf("download attachment: %w", err)
	}
	return data, nil
}

// IsParseable returns true if the attachment has a file extension we can extract text from.
func IsParseable(filename string) bool {
	lower := strings.ToLower(filename)
	return strings.HasSuffix(lower, ".docx") || strings.HasSuffix(lower, ".pdf")
}
