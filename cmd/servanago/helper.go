package main

import (
	"log/slog"

	"github.com/servanago/servanago/internal/helper"
)

// runHelper serves the privileged helper: a root daemon (systemd runs it as servanago-helper.service)
// answering typed actions from the control plane over /run/servanago/helper.sock.
func runHelper() error {
	// A host without the servanago user allows only root peers.
	uid, hasUser := helper.HelperUID()
	if !hasUser {
		uid = ^uint32(0) // no real uid matches: root clients only
	}
	ln, err := helper.Listen()
	if err != nil {
		return err
	}
	defer ln.Close()
	acts := map[string]helper.Action{
		helper.ActionPing:        func(helper.Request) helper.Response { return helper.Response{OK: true} },
		helper.ActionUnitInstall: helper.NewActions(helper.RealSeam{}).UnitInstall,
	}
	slog.Info("helper listening", "socket", helper.SocketPath, "servanago_user", hasUser)
	helper.Serve(ln, helper.NewAuthorizer(uid), acts)
	return nil
}
