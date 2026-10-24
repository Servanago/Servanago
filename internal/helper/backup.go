package helper

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/servanago/servanago/internal/backup"
)

// backup.go: the backup job's actions. The job itself (`servanago backup-job`, internal/backup) does the work as
// root under one fixed unit; these actions only install the units, hand it a request and report on it.
// Nothing secret passes through here: the job reads its plan from SQLite and the key from the environment file.

const (
	backupService = "servanago-backup.service"
	backupTimer   = "servanago-backup.timer"
	// BackupJobDir holds request.json, which the job reads once and deletes.
	BackupJobDir      = "/var/lib/servanago-backup"
	BackupRequestFile = "request.json"
	backupEnvFile     = "/etc/servanago/servanago.env"
	backupTimerSpec   = "*:00/15"
	backupActorRE     = `^[A-Za-z0-9._@-]{1,64}$`
	backupScopeAll    = "all"
	backupScopePanel  = "panel"
	backupScopeSite   = "site"
)

var actorRE = regexp.MustCompile(backupActorRE)

// BackupRequestData is the job's one-shot instruction. Every field is set by an action after validation.
type BackupRequestData struct {
	Op      string   `json:"op"`    // run | restore
	Scope   string   `json:"scope"` // all | panel | site
	Slug    string   `json:"slug,omitempty"`
	Archive string   `json:"archive,omitempty"`
	Files   bool     `json:"files,omitempty"`
	Dumps   bool     `json:"dumps,omitempty"`
	Actor   string   `json:"actor,omitempty"`
	Volumes []string `json:"volumes,omitempty"`
}

// backupUnits renders the service and its timer. Type=exec so `systemctl start` returns once the job runs: a oneshot
// would make the helper wait for the whole backup. ProtectSystem=full (not strict) because a restore writes into
// admin-chosen site roots anywhere on the host.
func backupUnits(exe string) (service, timer []byte) {
	service = []byte(fmt.Sprintf(`[Unit]
Description=ServanaGo backup job
[Service]
Type=exec
User=root
EnvironmentFile=-%s
ExecStart=%s backup-job run
Nice=10
IOSchedulingClass=idle
MemoryMax=2G
TimeoutStartSec=infinity
RuntimeMaxSec=8h
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectKernelTunables=yes
ProtectControlGroups=yes
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER
`, backupEnvFile, exe))
	timer = []byte(fmt.Sprintf(`[Unit]
Description=ServanaGo backup schedule check
[Timer]
OnCalendar=%s
Persistent=yes
Unit=%s
[Install]
WantedBy=timers.target
`, backupTimerSpec, backupService))
	return service, timer
}

// BackupEnable installs and starts the timer, or stops and disables it. The job refuses to run without a passphrase,
// which it finds in SQLite; the web layer checks that before it calls here.
func (a Actions) BackupEnable(r Request) Response {
	if !r.Vals.Enabled {
		if _, err := a.s.Lstat(systemdUnitDir + "/" + backupTimer); err != nil { // never installed: nothing to disable
			return Response{OK: true}
		}
		_ = a.s.StopUnit(backupTimer)
		if err := a.s.DisableUnit(backupTimer); err != nil {
			return Response{Error: fmt.Sprintf("systemctl disable %s: %v", backupTimer, err)}
		}
		return Response{OK: true}
	}
	exe, err := a.s.Exe()
	if err != nil {
		return Response{Error: fmt.Sprintf("find the servanago binary: %v", err)}
	}
	if err := validateRoot(exe, false); err != nil { // it is written into a unit file
		return Response{Error: fmt.Sprintf("servanago binary path: %v", err)}
	}
	if err := a.s.MkdirAll(BackupJobDir, 0o700); err != nil {
		return Response{Error: fmt.Sprintf("create %s: %v", BackupJobDir, err)}
	}
	svc, tmr := backupUnits(exe)
	if resp := a.put(systemdUnitDir+"/"+backupService, svc, a.s.VerifyUnit); !resp.OK {
		return resp
	}
	if resp := a.put(systemdUnitDir+"/"+backupTimer, tmr, a.s.VerifyUnit); !resp.OK {
		return resp
	}
	if err := a.s.DaemonReload(); err != nil {
		return Response{Error: fmt.Sprintf("systemctl daemon-reload: %v", err)}
	}
	if err := a.s.Enable(backupTimer); err != nil {
		return Response{Error: fmt.Sprintf("systemctl enable %s: %v", backupTimer, err)}
	}
	if err := a.s.StartUnit(backupTimer); err != nil {
		return Response{Error: fmt.Sprintf("systemctl start %s: %v", backupTimer, err)}
	}
	return Response{OK: true}
}

func (a Actions) backupActive() bool {
	st, err := a.s.UnitStatus(backupService)
	return err == nil && (st.ActiveState == "active" || st.ActiveState == "activating")
}

// start validates the request, writes it, and starts the job unless one is running.
func (a Actions) backupStart(req BackupRequestData) Response {
	if req.Actor != "" && !actorRE.MatchString(req.Actor) {
		return Response{Error: fmt.Sprintf("actor %q is not a valid user name", req.Actor)}
	}
	if a.backupActive() {
		return Response{Error: "a backup job is already running; wait for it to finish"}
	}
	if _, err := a.s.Lstat(systemdUnitDir + "/" + backupService); err != nil {
		return Response{Error: "backups are not enabled yet: enable them first"}
	}
	b, _ := json.Marshal(req)
	if err := a.s.MkdirAll(BackupJobDir, 0o700); err != nil {
		return Response{Error: fmt.Sprintf("create %s: %v", BackupJobDir, err)}
	}
	if err := a.s.WriteFile(filepath.Join(BackupJobDir, BackupRequestFile), b, 0o600); err != nil {
		return Response{Error: fmt.Sprintf("write the backup request: %v", err)}
	}
	if err := a.s.StartUnit(backupService); err != nil {
		return Response{Error: fmt.Sprintf("systemctl start %s: %v", backupService, err)}
	}
	return Response{OK: true}
}

// BackupStart runs one scope (or all enabled ones) now, whether or not it is due.
func (a Actions) BackupStart(r Request) Response {
	v := r.Vals
	req := BackupRequestData{Op: "run", Scope: v.Scope, Actor: v.Actor}
	switch v.Scope {
	case backupScopeAll, backupScopePanel:
	case backupScopeSite:
		slug, err := r.Slug()
		if err != nil {
			return Response{Error: err.Error()}
		}
		req.Slug = slug
	default:
		return Response{Error: fmt.Sprintf("scope %q must be all, panel or site", v.Scope)}
	}
	return a.backupStart(req)
}

// BackupRestore restores one site from one archive of its own scope. Volumes are never restored here.
func (a Actions) BackupRestore(r Request) Response {
	slug, err := r.Slug()
	if err != nil {
		return Response{Error: err.Error()}
	}
	v := r.Vals
	if !backup.ValidName(v.Archive) || !strings.HasPrefix(v.Archive, slug+"-") {
		return Response{Error: fmt.Sprintf("archive %q is not an archive of site %s", v.Archive, slug)}
	}
	if !v.RestoreFiles && !v.RestoreDumps && len(v.RestoreVolumes) == 0 {
		return Response{Error: "choose what to restore: files, dumps, volumes or any of them"}
	}
	if len(v.RestoreVolumes) > 20 {
		return Response{Error: "at most 20 volumes in one restore"}
	}
	seen := map[string]bool{}
	for _, vol := range v.RestoreVolumes {
		if !backup.ValidVolume(vol) || seen[vol] {
			return Response{Error: fmt.Sprintf("volume %q is not a valid, distinct volume name", vol)}
		}
		seen[vol] = true
	}
	return a.backupStart(BackupRequestData{Op: "restore", Scope: backupScopeSite, Slug: slug, Archive: v.Archive, Files: v.RestoreFiles, Dumps: v.RestoreDumps, Volumes: v.RestoreVolumes, Actor: v.Actor})
}

// BackupStatus reports the job unit's state and the tail of its journal.
func (a Actions) BackupStatus(Request) Response {
	st, err := a.s.UnitStatus(backupService)
	if err != nil {
		return Response{OK: true, Status: &StatusData{ActiveState: "not-installed"}}
	}
	logs, _ := a.s.UnitLogs(backupService, defaultLogLines)
	return Response{OK: true, Status: &st, Logs: logs}
}

// ValidateSiteRoot is the check the backup job applies to a site root before it reads or writes there: the helper's own
// path rules and its deny list, never the web layer's.
func ValidateSiteRoot(root string) error { return validateSiteRoot(root, false) }
