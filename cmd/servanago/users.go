package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/servanago/servanago/internal/config"
)

// runUser implements `servanago user add NAME` and `servanago user passwd NAME`: recovery and bootstrap without a
// session, reading DATA_DIR only. askPassword supplies the new password (a prompt on a terminal, a line on stdin otherwise).
func runUser(args []string, askPassword func() (string, error), out io.Writer) error {
	const usage = "usage: servanago user add NAME | servanago user passwd NAME"
	if len(args) != 2 || (args[0] != "add" && args[0] != "passwd") {
		return errors.New(usage)
	}
	name := strings.ToLower(strings.TrimSpace(args[1]))
	if err := config.ValidateUsername(name); err != nil {
		return err
	}
	st, err := openDataStore()
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	u, exists, err := st.GetUserByName(ctx, name)
	if err != nil {
		return err
	}
	switch {
	case args[0] == "add" && exists:
		return fmt.Errorf("user %q already exists (use: servanago user passwd %s)", name, name)
	case args[0] == "passwd" && !exists:
		return fmt.Errorf("no user named %q (use: servanago user add %s)", name, name)
	}
	pw, err := askPassword()
	if err != nil {
		return err
	}
	if err := config.ValidatePassword(pw); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if args[0] == "add" {
		if _, err := st.CreateUser(ctx, name, string(hash)); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "added administrator %s\n", name)
		return err
	}
	if err := st.SetPassword(ctx, u.ID, string(hash)); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "password set for %s; their open sessions have ended\n", name)
	return err
}

// terminalPassword asks twice without echo on a terminal, or reads one line from a pipe (printf 'pw\n' | servanago user add NAME).
func terminalPassword() (string, error) {
	fd := int(syscall.Stdin)
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", errors.New("no password on stdin")
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	read := func(prompt string) ([]byte, error) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return b, err
	}
	first, err := read("Password: ")
	if err != nil {
		return "", err
	}
	second, err := read("Again: ")
	if err != nil {
		return "", err
	}
	if !bytes.Equal(first, second) {
		return "", errors.New("the two passwords differ")
	}
	return string(first), nil
}
