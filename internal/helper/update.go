package helper

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/servanago/servanago/internal/update"
)

// update.go: the one privileged step of the updater. The caller says which version it saw; the helper fetches and
// verifies the signed manifest itself, then starts the root upgrade job (`servanago update-job`) under its own
// unit, so the job outlives the helper that dpkg's prerm stops. No URL, path or architecture comes from the caller.

const (
	updateService = "servanago-upgrade.service"
	// UpdateJobDir holds job.json, which the job reads; the web user can read the directory but not write to it.
	UpdateJobDir  = "/var/lib/servanago-update"
	UpdateJobFile = "job.json"
	updateEnvFile = "/etc/servanago/servanago.env"
	maxManifest   = 64 << 10
)

var releaseRE = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// UpdateJob is the job's one-shot instruction: the verified manifest and its signature (the job verifies them
// again), the version being replaced and who asked.
type UpdateJob struct {
	Manifest string `json:"manifest"`
	Sig      string `json:"sig"`
	From     string `json:"from"`
	Actor    string `json:"actor,omitempty"`
}

func updateUnit(exe string) []byte {
	return []byte(fmt.Sprintf(`[Unit]
Description=ServanaGo upgrade job
[Service]
Type=exec
User=root
EnvironmentFile=-%s
ExecStart=%s update-job
TimeoutStartSec=infinity
RuntimeMaxSec=1h
`, updateEnvFile, exe))
}

// UpdateStart verifies the latest signed release and starts the upgrade job for it.
func (a Actions) UpdateStart(r Request) Response {
	v := r.Vals
	if !releaseRE.MatchString(v.UpdateVersion) {
		return Response{Error: fmt.Sprintf("version %q must look like 1.2.3", v.UpdateVersion)}
	}
	if v.Actor != "" && !actorRE.MatchString(v.Actor) {
		return Response{Error: fmt.Sprintf("actor %q is not a valid user name", v.Actor)}
	}
	if !releaseRE.MatchString(a.version) {
		return Response{Error: "this is a source build; install a release package to use the updater"}
	}
	for _, u := range []string{updateService, fetchUnit, buildUnit, backupService} {
		if st, err := a.s.UnitStatus(u); err == nil && (st.ActiveState == "active" || st.ActiveState == "activating") {
			return Response{Error: fmt.Sprintf("%s is running; wait for it to finish", u)}
		}
	}
	mf, err := a.s.Fetch(update.ManifestURL, maxManifest)
	if err != nil {
		return Response{Error: fmt.Sprintf("fetch the release manifest: %v", err)}
	}
	sig, err := a.s.Fetch(update.SigURL, maxManifest)
	if err != nil {
		return Response{Error: fmt.Sprintf("fetch the manifest signature: %v", err)}
	}
	m, err := update.Verify(a.keys, mf, sig)
	if err != nil {
		return Response{Error: err.Error()}
	}
	if m.Version != v.UpdateVersion {
		return Response{Error: fmt.Sprintf("the latest release is %s, not %s", m.Version, v.UpdateVersion)}
	}
	if !update.Newer(a.version, m.Version) {
		return Response{Error: fmt.Sprintf("%s is not newer than the running %s", m.Version, a.version)}
	}
	if update.Newer(a.version, m.MinUpgradeFrom) {
		return Response{Error: fmt.Sprintf("this release cannot be installed over %s: upgrade to %s first", a.version, m.MinUpgradeFrom)}
	}
	if _, ok := m.Debs[runtime.GOARCH]; !ok {
		return Response{Error: fmt.Sprintf("release %s has no package for %s", m.Version, runtime.GOARCH)}
	}
	exe, err := a.s.Exe()
	if err != nil {
		return Response{Error: fmt.Sprintf("find the servanago binary: %v", err)}
	}
	if err := validateRoot(exe, false); err != nil { // it is written into a unit file
		return Response{Error: fmt.Sprintf("servanago binary path: %v", err)}
	}
	job, _ := json.Marshal(UpdateJob{Manifest: string(mf), Sig: string(sig), From: a.version, Actor: v.Actor})
	if err := a.s.MkdirAll(UpdateJobDir, 0o755); err != nil {
		return Response{Error: fmt.Sprintf("create %s: %v", UpdateJobDir, err)}
	}
	if err := a.s.WriteFile(filepath.Join(UpdateJobDir, UpdateJobFile), job, 0o600); err != nil {
		return Response{Error: fmt.Sprintf("write the upgrade job: %v", err)}
	}
	if resp := a.put(systemdUnitDir+"/"+updateService, updateUnit(exe), a.s.VerifyUnit); !resp.OK {
		return resp
	}
	if err := a.s.DaemonReload(); err != nil {
		return Response{Error: fmt.Sprintf("systemctl daemon-reload: %v", err)}
	}
	if err := a.s.StartUnit(updateService); err != nil {
		return Response{Error: fmt.Sprintf("systemctl start %s: %v", updateService, err)}
	}
	return Response{OK: true}
}
