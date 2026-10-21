// Package phpbuild is the PHP build job: `servanago php-job fetch|build DIR` runs as the unprivileged
// sg-phpbuild user under two fixed systemd units (see internal/helper). This file holds what the helper
// (which starts the job and installs its output) and the job (which does the work) share.
package phpbuild

// Dir is the job's work directory: job.json (input), state.json (progress), src/ and work/ (downloads and
// compilation), root/ (bind-mounted at /opt/servanago/php while the build runs, so every prefix is its final path).
// It is outside /var/lib/servanago, which is 0750 servanago:servanago: the job runs as sg-phpbuild and could not reach it.
const Dir = "/var/lib/servanago-build/current"

const (
	JobFile   = "job.json"
	StateFile = "state.json"
)

// Job is the helper's instruction to the job. N is the build number, decided before the build because the
// prefix /opt/servanago/php/<version>-<n> is compiled into the binaries.
type Job struct {
	Version string `json:"version"` // 8.4.27
	N       int    `json:"n"`
	Jobs    int    `json:"jobs"` // make -j
}

// Label is the build directory name: 8.4.27-1.
func (j Job) Label() string { return labelOf(j.Version, j.N) }

// State phases.
const (
	PhaseIdle     = "idle"
	PhaseFetching = "fetching"
	PhaseBuilding = "building"
	PhaseBuilt    = "built"
	PhaseFailed   = "failed"
)

// State is the job's progress, read by the helper's php-status.
type State struct {
	Phase   string `json:"phase"`
	Version string `json:"version,omitempty"`
	N       int    `json:"n,omitempty"`
	Message string `json:"message,omitempty"`
}
