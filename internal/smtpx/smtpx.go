// Package smtpx sends one magic-link email over submission SMTP with stdlib net/smtp.
// Host and credentials come from the settings row (the password is sealed at rest).
package smtpx

import (
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
)

type Dialer struct {
	Host string
	Port int
	User string // empty = no authentication
	Pass string
}

func (d Dialer) Configured() bool { return d.Host != "" }

// Send is the whole mailer contract; body is plain text with \n newlines.
func (d Dialer) Send(from, to, subject, body string) error {
	if !d.Configured() {
		return fmt.Errorf("SMTP host is not set")
	}
	msg := "From: " + from + "\r\nTo: " + to + "\r\nSubject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
		strings.ReplaceAll(body, "\r\n", "\n")
	var auth smtp.Auth
	if d.User != "" {
		auth = smtp.PlainAuth("", d.User, d.Pass, d.Host)
	}
	return smtp.SendMail(net.JoinHostPort(d.Host, strconv.Itoa(d.Port)), auth, from, []string{to}, []byte(msg))
}
