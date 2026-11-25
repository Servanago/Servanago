package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/servanago/servanago/internal/secretbox"
	"github.com/servanago/servanago/internal/smtpx"
	"github.com/servanago/servanago/internal/store"
)

// Open unseals a stored destination. A destination whose values cannot be opened (the key changed) is reported, not sent.
func Open(key string, d store.AlertDest) (Dest, error) {
	out := Dest{ID: d.ID, Name: d.Name, Kind: d.Kind}
	if key == "" {
		return out, fmt.Errorf("SERVANAGO_SECRET_KEY is not set")
	}
	t, err := secretbox.Open(key, d.Target)
	if err != nil {
		return out, fmt.Errorf("the stored address cannot be opened with this secret key")
	}
	out.Target = string(t)
	if d.Secret != nil {
		s, err := secretbox.Open(key, d.Secret)
		if err != nil {
			return out, fmt.Errorf("the stored secret cannot be opened with this secret key")
		}
		out.Secret = string(s)
	}
	return out, nil
}

// StoreResolver routes an event to the stored destinations: each destination's own event list, narrowed by the site's override.
func StoreResolver(st *store.Store, key string) func(ctx context.Context, ev Event) ([]Dest, error) {
	return func(ctx context.Context, ev Event) ([]Dest, error) {
		all, err := st.ListAlertDests(ctx)
		if err != nil {
			return nil, err
		}
		var only []int64
		if ev.Site != "" {
			if only, err = st.SiteAlertDestIDs(ctx, ev.Site); err != nil {
				return nil, err
			}
		}
		var out []Dest
		for _, d := range store.RouteAlert(all, only, ev.Kind) {
			o, err := Open(key, d)
			if err != nil {
				slog.Warn("alert destination skipped", "destination", d.Name, "error", err)
				_ = st.SetAlertDestError(ctx, d.ID, err.Error(), time.Now().Unix())
				continue
			}
			out = append(out, o)
		}
		return out, nil
	}
}

// StoreResult records a delivery outcome on the destination row (/alerts shows the last error).
func StoreResult(st *store.Store) func(d Dest, err error) {
	return func(d Dest, err error) {
		msg, at := "", int64(0)
		if err != nil {
			msg, at = err.Error(), time.Now().Unix()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e := st.SetAlertDestError(ctx, d.ID, msg, at); e != nil {
			slog.Warn("alert result not recorded", "error", e)
		}
	}
}

// MailSource gives the email kind the Settings page's SMTP delivery, the password opened only at send time.
func MailSource(st *store.Store, key string) func() (smtpx.Dialer, string) {
	return func() (smtpx.Dialer, string) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		set, err := st.GetSettings(ctx)
		if err != nil || !set.MailReady() {
			return smtpx.Dialer{}, ""
		}
		pass := ""
		if set.SMTPPass != nil {
			b, err := secretbox.Open(key, set.SMTPPass)
			if err != nil {
				return smtpx.Dialer{}, ""
			}
			pass = string(b)
		}
		return smtpx.Dialer{Host: set.SMTPHost, Port: set.SMTPPort, User: set.SMTPUser, Pass: pass}, set.MailFrom
	}
}
