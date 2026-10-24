package helper

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestBackupEnableInstallsUnitsAndTimer(t *testing.T) {
	seam := newFakeSeam()
	seam.exe = "/usr/bin/servanago"
	resp := NewActions(seam).BackupEnable(req(t, ActionBackupEnable, `{"enabled":true}`))
	if !resp.OK {
		t.Fatalf("%+v", resp)
	}
	svc, tmr := string(seam.written[systemdUnitDir+"/"+backupService]), string(seam.written[systemdUnitDir+"/"+backupTimer])
	for _, want := range []string{"User=root", "ExecStart=/usr/bin/servanago backup-job run", "Type=exec", "Nice=10", "NoNewPrivileges=yes", "EnvironmentFile=-/etc/servanago/servanago.env"} {
		if !strings.Contains(svc, want) {
			t.Errorf("service missing %q:\n%s", want, svc)
		}
	}
	if !strings.Contains(tmr, "OnCalendar=*:00/15") || !strings.Contains(tmr, "Persistent=yes") {
		t.Errorf("timer:\n%s", tmr)
	}
	if seam.enabled != backupTimer || seam.started != backupTimer || seam.reloadCalls != 1 {
		t.Errorf("enabled %q started %q reloads %d", seam.enabled, seam.started, seam.reloadCalls)
	}
}

func TestBackupEnableRefusesAnExeThatCouldInjectIntoTheUnit(t *testing.T) {
	seam := newFakeSeam()
	seam.exe = "/opt/my servanago\nExecStartPre=/bin/evil"
	if resp := NewActions(seam).BackupEnable(req(t, ActionBackupEnable, `{"enabled":true}`)); resp.OK || !strings.Contains(resp.Error, "servanago binary path") {
		t.Fatalf("%+v", resp)
	}
	if len(seam.written) != 0 {
		t.Errorf("wrote %v", seam.written)
	}
}

func TestBackupDisable(t *testing.T) {
	seam := newFakeSeam()
	if resp := NewActions(seam).BackupEnable(req(t, ActionBackupEnable, `{}`)); !resp.OK || seam.disabled != "" {
		t.Fatalf("never installed: %+v disabled %q", resp, seam.disabled)
	}
	seam.files = map[string][]byte{systemdUnitDir + "/" + backupTimer: nil}
	if resp := NewActions(seam).BackupEnable(req(t, ActionBackupEnable, `{}`)); !resp.OK || seam.disabled != backupTimer || seam.stopped != backupTimer {
		t.Fatalf("%+v disabled %q stopped %q", resp, seam.disabled, seam.stopped)
	}
}

func installed(seam *fakeSeam) *fakeSeam {
	seam.files = map[string][]byte{systemdUnitDir + "/" + backupService: nil}
	return seam
}

func TestBackupStartWritesOnlyValidatedRequest(t *testing.T) {
	seam := installed(newFakeSeam())
	resp := NewActions(seam).BackupStart(req(t, ActionBackupStart, `{"scope":"site","slug":"shop","actor":"brian"}`))
	if !resp.OK || seam.started != backupService {
		t.Fatalf("%+v started %q", resp, seam.started)
	}
	var got BackupRequestData
	if err := json.Unmarshal(seam.written[BackupJobDir+"/"+BackupRequestFile], &got); err != nil || got.Op != "run" || got.Slug != "shop" || got.Actor != "brian" {
		t.Errorf("request %+v %v", got, err)
	}
}

func TestBackupRejections(t *testing.T) {
	for _, tc := range []struct {
		name, action, spec, want string
		setup                    func(*fakeSeam)
	}{
		{"unknown scope", ActionBackupStart, `{"scope":"everything"}`, "must be all, panel or site", nil},
		{"site needs slug", ActionBackupStart, `{"scope":"site"}`, "slug", nil},
		{"bad slug", ActionBackupStart, `{"scope":"site","slug":"../x"}`, "slug", nil},
		{"actor injection", ActionBackupStart, `{"scope":"all","actor":"a\"b"}`, "not a valid user name", nil},
		{"not enabled", ActionBackupStart, `{"scope":"all"}`, "not enabled", func(s *fakeSeam) { s.files = nil }},
		{"already running", ActionBackupStart, `{"scope":"all"}`, "already running", func(s *fakeSeam) { s.status = StatusData{ActiveState: "active"} }},
		{"restore other site's archive", ActionBackupRestore, `{"slug":"shop","archive":"blog-20260101T000000Z.tar.zst.age","restore_files":true}`, "not an archive of site shop", nil},
		{"restore traversal", ActionBackupRestore, `{"slug":"shop","archive":"../shop-20260101T000000Z.tar.zst.age","restore_files":true}`, "not an archive of site", nil},
		{"restore nothing", ActionBackupRestore, `{"slug":"shop","archive":"shop-20260101T000000Z.tar.zst.age"}`, "choose what to restore", nil},
		{"restore bad volume", ActionBackupRestore, `{"slug":"shop","archive":"shop-20260101T000000Z.tar.zst.age","restore_volumes":["../x"]}`, "not a valid, distinct volume", nil},
		{"restore duplicate volume", ActionBackupRestore, `{"slug":"shop","archive":"shop-20260101T000000Z.tar.zst.age","restore_volumes":["a","a"]}`, "not a valid, distinct volume", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seam := installed(newFakeSeam())
			if tc.setup != nil {
				tc.setup(seam)
			}
			a := NewActions(seam)
			f := a.BackupStart
			if tc.action == ActionBackupRestore {
				f = a.BackupRestore
			}
			resp := f(req(t, tc.action, tc.spec))
			if resp.OK || !strings.Contains(resp.Error, tc.want) {
				t.Fatalf("%+v, want an error mentioning %q", resp, tc.want)
			}
			if seam.started != "" || len(seam.written) != 0 {
				t.Errorf("a refused request still started %q / wrote %v", seam.started, seam.written)
			}
		})
	}
}

func TestBackupRestoreAccepted(t *testing.T) {
	seam := installed(newFakeSeam())
	resp := NewActions(seam).BackupRestore(req(t, ActionBackupRestore, `{"slug":"shop","archive":"shop-20260101T000000Z.tar.zst.age","restore_files":true,"restore_volumes":["data"],"actor":"brian"}`))
	if !resp.OK {
		t.Fatalf("%+v", resp)
	}
	var got BackupRequestData
	_ = json.Unmarshal(seam.written[BackupJobDir+"/"+BackupRequestFile], &got)
	if got.Op != "restore" || got.Archive != "shop-20260101T000000Z.tar.zst.age" || !got.Files || got.Dumps || len(got.Volumes) != 1 || got.Volumes[0] != "data" {
		t.Errorf("%+v", got)
	}
}

func TestBackupStatusWhenNotInstalled(t *testing.T) {
	seam := newFakeSeam()
	seam.statusErr = errors.New("Unit servanago-backup.service could not be found")
	if resp := NewActions(seam).BackupStatus(req(t, ActionBackupStatus, `{}`)); !resp.OK || resp.Status.ActiveState != "not-installed" {
		t.Fatalf("%+v", resp)
	}
}
