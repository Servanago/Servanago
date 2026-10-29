// Scan alerts as ntfy posts. The backup job has its own simpler sender (failures only); scan
// alerts carry a priority, a title and an optional access token.
package scan

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Notify posts one alert to the ntfy topic URL at priority urgent; token may be empty.
func Notify(ctx context.Context, url, token, title, body string) error {
	if !strings.HasPrefix(url, "https://") {
		return errors.New("the ntfy address must be an https:// URL")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", title)
	req.Header.Set("Priority", "urgent")
	req.Header.Set("Tags", "warning")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	c := http.Client{CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("refusing a redirect to a non-https URL")
		}
		return nil
	}}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
