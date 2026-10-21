package phpbuild

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/servanago/servanago/internal/phplibs"
)

// retryDelay is the pause before each retry; a variable so the test does not wait.
var retryDelay = []time.Duration{2 * time.Second, 6 * time.Second}

// HTTPGet is the job's real Getter: https only for redirects, a size cap, no credentials. A network error or a 5xx answer
// is retried twice (mirrors drop connections); a 4xx or a size error is final. What comes back is only ever used after
// its checksum matches, so retrying is safe.
func HTTPGet(ctx context.Context, url string) ([]byte, error) {
	b, err := httpGetOnce(ctx, url)
	for _, d := range retryDelay {
		if err == nil || !retryable(err) || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(d):
		}
		b, err = httpGetOnce(ctx, url)
	}
	return b, err
}

type statusError struct{ code int }

func (e statusError) Error() string { return fmt.Sprintf("http status %d", e.code) }

func retryable(err error) bool {
	var se statusError
	if errors.As(err, &se) {
		return se.code >= 500
	}
	return !strings.Contains(err.Error(), "larger than") && !strings.Contains(err.Error(), "refusing redirect")
}

func httpGetOnce(ctx context.Context, url string) ([]byte, error) {
	const limit = 300 << 20
	client := &http.Client{
		Timeout: 10 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || len(via) > 8 {
				return fmt.Errorf("refusing redirect to %s", req.URL)
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "servanago-php-job")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s: %w", url, resp.Status, statusError{resp.StatusCode})
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("%s: larger than %d MB", url, limit>>20)
	}
	return b, nil
}

// RunCmd runs one build command in its directory, with the recipe's environment added to this one's. Output goes to
// stdout/stderr, which the unit sends to the journal.
func RunCmd(ctx context.Context, c phplibs.Cmd) error {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Dir = c.Dir
	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}
