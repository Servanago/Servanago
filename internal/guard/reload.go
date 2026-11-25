package guard

import (
	"context"
	"fmt"

	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/store"
)

// Reload reads the guard settings row and installs it: ban rules, retention and the x402 wallet. Called at startup and after the form saves.
func (s *Service) Reload(ctx context.Context, st *store.Store, secretKey string) error {
	g, err := st.GetGuardSettings(ctx)
	if err != nil {
		return err
	}
	s.SetSettings(g)
	s.SetRetention(g.LogDays, g.RollupDays)
	conf := X402Config{Facilitator: g.X402Facilitator, Network: g.X402Network, PayTo: g.X402PayTo}
	if len(g.X402APIKey) > 0 && secretKey != "" {
		b, err := secretbox.Open(secretKey, g.X402APIKey)
		if err != nil {
			return fmt.Errorf("the x402 facilitator key cannot be opened with this secret key")
		}
		conf.APIKey = string(b)
	}
	s.SetX402(conf)
	return nil
}
