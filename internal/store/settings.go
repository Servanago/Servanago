// App settings (email delivery, backups, virus scanning). The caller seals the SMTP password and
// the ntfy secrets; SaveSettings never sees plaintext.
package store

import (
	"context"
	"fmt"
)

type Settings struct {
	SMTPHost  string
	SMTPPort  int
	SMTPUser  string
	SMTPPass  []byte // secretbox blob, nil = none
	MailFrom  string
	UpdatedAt string
	// Virus scanning: the clamd socket path (empty = scanning off), the daily sweep hour and the
	// alert ntfy topic; the secrets are secretbox blobs.
	ScanSocket    string
	ScanHour      int
	ScanNtfy      []byte
	ScanNtfyToken []byte
	// Country blocking for the panel: the mmdb file (geoipupdate keeps it fresh, empty = geo off)
	// and the panel's own country rule.
	GeoDB          string
	WebUIMode      string // "" | deny | allow
	WebUICountries string
	// Postmark mail bridge: the sealed account token (nil = bridge off) and the global LMTP target
	// the inbound webhooks deliver to. The password is secretbox-sealed.
	MailToken []byte
	MailLMTP  string
	MailTLS   string // "" | starttls
	MailUser  string
	MailPass  []byte
}

const settingsCols = "smtp_host, smtp_port, smtp_user, smtp_pass, mail_from, updated_at, scan_socket, scan_hour, scan_ntfy, scan_ntfy_token, geo_db, webui_mode, webui_countries, mail_pm_token, mail_lmtp, mail_lmtp_tls, mail_lmtp_user, mail_lmtp_pass"

func (s *Store) GetSettings(ctx context.Context) (Settings, error) {
	var st Settings
	err := s.q.QueryRowContext(ctx,
		`SELECT `+settingsCols+` FROM settings WHERE id=1`).
		Scan(&st.SMTPHost, &st.SMTPPort, &st.SMTPUser, &st.SMTPPass, &st.MailFrom, &st.UpdatedAt,
			&st.ScanSocket, &st.ScanHour, &st.ScanNtfy, &st.ScanNtfyToken,
			&st.GeoDB, &st.WebUIMode, &st.WebUICountries,
			&st.MailToken, &st.MailLMTP, &st.MailTLS, &st.MailUser, &st.MailPass)
	if err != nil {
		return st, fmt.Errorf("read settings: %w", err)
	}
	return st, nil
}

func (s *Store) SaveSettings(ctx context.Context, st Settings) error {
	if _, err := s.q.ExecContext(ctx,
		`UPDATE settings SET smtp_host=?, smtp_port=?, smtp_user=?, smtp_pass=?, mail_from=?, updated_at=?, scan_socket=?, scan_hour=?, scan_ntfy=?, scan_ntfy_token=?, geo_db=?, webui_mode=?, webui_countries=?, mail_pm_token=?, mail_lmtp=?, mail_lmtp_tls=?, mail_lmtp_user=?, mail_lmtp_pass=? WHERE id=1`,
		st.SMTPHost, st.SMTPPort, st.SMTPUser, st.SMTPPass, st.MailFrom, st.UpdatedAt,
		st.ScanSocket, st.ScanHour, st.ScanNtfy, st.ScanNtfyToken,
		st.GeoDB, st.WebUIMode, st.WebUICountries,
		st.MailToken, st.MailLMTP, st.MailTLS, st.MailUser, st.MailPass); err != nil {
		return fmt.Errorf("save settings: %w", err)
	}
	return nil
}

// MailReady is true when the row can deliver: host and sender set.
func (st Settings) MailReady() bool { return st.SMTPHost != "" && st.MailFrom != "" }
