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
	a := helper.NewActions(helper.RealSeam{})
	acts := map[string]helper.Action{
		helper.ActionPing:        func(helper.Request) helper.Response { return helper.Response{OK: true} },
		helper.ActionUnitInstall: a.UnitInstall,
		helper.ActionUnitStatus:  a.UnitStatus,
		helper.ActionUnitLogs:    a.UnitLogs,
		helper.ActionUserAdd:     a.UserAdd,
		helper.ActionUserRemove:  a.UserRemove,
		helper.ActionUnitRemove:  a.UnitRemove,
		helper.ActionUnitStart:   a.UnitStart,
		helper.ActionUnitStop:    a.UnitStop,

		helper.ActionPHPBuild:       a.PHPBuild,
		helper.ActionPHPStatus:      a.PHPStatus,
		helper.ActionPHPInstall:     a.PHPInstall,
		helper.ActionPHPPrune:       a.PHPPrune,
		helper.ActionPHPUserDefault: a.PHPUserDefault,
		helper.ActionComposer:       a.Composer,
	}
	slog.Info("helper listening", "socket", helper.SocketPath, "servanago_user", hasUser)
	helper.Serve(ln, helper.NewAuthorizer(uid), acts)
	return nil
}
