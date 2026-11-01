package helper

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/servanago/servanago/internal/update"
)

// updateSeam is a fake host whose "GitHub" serves a manifest for ver signed by the key a.keys trusts.
func updateActions(t testing.TB, running, ver, minFrom string) (Actions, *fakeSeam) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	deb := filepath.Join(t.TempDir(), "servanago_"+ver+"_"+runtime.GOARCH+".deb")
	if err := os.WriteFile(deb, []byte("deb"), 0o600); err != nil {
		t.Fatal(err)
	}
	mf, err := update.Build(deb, "https://example.test/notes", minFrom, false, false)
	if err != nil {
		t.Fatal(err)
	}
	seam := newFakeSeam()
	seam.exe = "/usr/bin/servanago"
	seam.fetched = map[string][]byte{update.ManifestURL: mf, update.SigURL: update.Sign(priv, mf)}
	a := NewActions(seam)
	a.keys, a.version = []ed25519.PublicKey{pub}, running
	return a, seam
}

func TestUpdateStartWritesTheJobAndStartsItsUnit(t *testing.T) {
	a, seam := updateActions(t, "0.18.0", "0.19.0", "0.5.0")
	resp := a.UpdateStart(req(t, ActionUpdateStart, `{"update_version":"0.19.0","actor":"brian"}`))
	if !resp.OK {
		t.Fatalf("%+v", resp)
	}
	if seam.started != updateService || seam.reloadCalls != 1 {
		t.Errorf("started %q reloads %d", seam.started, seam.reloadCalls)
	}
	unit := string(seam.written[systemdUnitDir+"/"+updateService])
	for _, want := range []string{"User=root", "ExecStart=/usr/bin/servanago update-job", "Type=exec"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit missing %q:\n%s", want, unit)
		}
	}
	var job UpdateJob
	if err := json.Unmarshal(seam.written[UpdateJobDir+"/"+UpdateJobFile], &job); err != nil {
		t.Fatal(err)
	}
	if job.From != "0.18.0" || job.Actor != "brian" || !strings.Contains(job.Manifest, `"0.19.0"`) || job.Sig == "" {
		t.Errorf("job %+v", job)
	}
}

func TestUpdateStartRejections(t *testing.T) {
	type tc struct {
		name, running, latest, minFrom, spec, want string
		busy, noKeys                               bool
	}
	ok := `{"update_version":"0.19.0"}`
	cases := []tc{
		{name: "source build", running: "dev", latest: "0.19.0", minFrom: "0.5.0", spec: ok, want: "source build"},
		{name: "not the latest", running: "0.18.0", latest: "0.19.0", minFrom: "0.5.0", spec: `{"update_version":"0.18.5"}`, want: "latest release is 0.19.0"},
		{name: "same version", running: "0.19.0", latest: "0.19.0", minFrom: "0.5.0", spec: ok, want: "not newer"},
		{name: "downgrade", running: "0.20.0", latest: "0.19.0", minFrom: "0.5.0", spec: ok, want: "not newer"},
		{name: "too old to upgrade directly", running: "0.4.0", latest: "0.19.0", minFrom: "0.5.0", spec: ok, want: "upgrade to 0.5.0 first"},
		{name: "bad version text", running: "0.18.0", latest: "0.19.0", minFrom: "0.5.0", spec: `{"update_version":"latest"}`, want: "version"},
		{name: "bad actor", running: "0.18.0", latest: "0.19.0", minFrom: "0.5.0", spec: `{"update_version":"0.19.0","actor":"a b\n"}`, want: "actor"},
		{name: "a build job is running", running: "0.18.0", latest: "0.19.0", minFrom: "0.5.0", spec: ok, busy: true, want: "running"},
		{name: "manifest not signed by a trusted key", running: "0.18.0", latest: "0.19.0", minFrom: "0.5.0", spec: ok, noKeys: true, want: "no trusted"},
	}
	for _, c := range cases {
		a, seam := updateActions(t, c.running, c.latest, c.minFrom)
		if c.busy {
			seam.status = StatusData{ActiveState: "active"}
		}
		if c.noKeys {
			a.keys = nil
		}
		resp := a.UpdateStart(req(t, ActionUpdateStart, c.spec))
		if resp.OK || !strings.Contains(resp.Error, c.want) {
			t.Errorf("%s: %+v, want error containing %q", c.name, resp, c.want)
		}
		if seam.started != "" || len(seam.written) != 0 {
			t.Errorf("%s: touched the host (started %q, wrote %d files)", c.name, seam.started, len(seam.written))
		}
	}
}

func TestUpdateStartRejectsATamperedManifest(t *testing.T) {
	a, seam := updateActions(t, "0.18.0", "0.19.0", "0.5.0")
	seam.fetched[update.ManifestURL] = []byte(strings.Replace(string(seam.fetched[update.ManifestURL]), "0.19.0", "0.19.1", 1))
	if resp := a.UpdateStart(req(t, ActionUpdateStart, `{"update_version":"0.19.1"}`)); resp.OK || !strings.Contains(resp.Error, "signature") {
		t.Fatalf("%+v", resp)
	}
	if seam.started != "" {
		t.Error("started a job for a tampered manifest")
	}
}

func TestUpdateStartRefusesAnExeThatCouldInjectIntoTheUnit(t *testing.T) {
	a, seam := updateActions(t, "0.18.0", "0.19.0", "0.5.0")
	seam.exe = "/opt/my servanago\nExecStartPre=/bin/evil"
	if resp := a.UpdateStart(req(t, ActionUpdateStart, `{"update_version":"0.19.0"}`)); resp.OK || !strings.Contains(resp.Error, "servanago binary path") {
		t.Fatalf("%+v", resp)
	}
	if len(seam.written) != 0 {
		t.Errorf("wrote %v", seam.written)
	}
}

// The request has no field that could carry a URL or a path: unknown fields are refused at decode.
func TestUpdateStartCarriesNoURLOrPath(t *testing.T) {
	for _, spec := range []string{`{"update_version":"0.19.0","url":"https://evil.example/x.deb"}`, `{"update_version":"0.19.0","path":"/tmp/x.deb"}`} {
		if _, err := DecodeRequest([]byte(`{"action":"update-start","spec":` + spec + `}`)); err == nil {
			t.Errorf("accepted %s", spec)
		}
	}
}

func FuzzUpdateStartVersionAndActor(f *testing.F) {
	for _, s := range []string{"0.19.0", "", "a", "0.19.0\nx", "../../x", "1.2.3.4"} {
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, version, actor string) {
		spec, _ := json.Marshal(Spec{UpdateVersion: version, Actor: actor})
		r, err := DecodeRequest([]byte(`{"action":"update-start","spec":` + string(spec) + `}`))
		if err != nil {
			return
		}
		a, seam := updateActions(t, "0.18.0", "0.19.0", "0.5.0")
		resp := a.UpdateStart(r)
		if resp.OK && (version != "0.19.0" || (actor != "" && !actorRE.MatchString(actor))) {
			t.Fatalf("accepted version %q actor %q", version, actor)
		}
		if !resp.OK && (seam.started != "" || len(seam.written) != 0) {
			t.Fatalf("rejected but touched the host: %q", version)
		}
	})
}
