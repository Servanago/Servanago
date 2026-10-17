package helper

import (
	"errors"
	"io/fs"
	"strconv"
	"testing"
)

// unit-status and unit-logs: typed reads for the dashboard's service panel (wired when units exist).
func TestUnitStatusAction(t *testing.T) {
	seam := newFakeSeam()
	seam.status = StatusData{ActiveState: "running", SubState: "running", PID: "123"}
	req, err := DecodeRequest([]byte(`{"action":"unit-status","spec":{"slug":"blog"}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp := NewActions(seam).UnitStatus(req)
	if !resp.OK || resp.Status == nil || resp.Status.ActiveState != "running" || resp.Status.PID != "123" {
		t.Fatalf("status: %+v", resp)
	}
	// The seam saw the helper-built unit name only.
	if seam.statusName != "servanago-blog.service" {
		t.Errorf("status asked for %q", seam.statusName)
	}
	// No unit: an error response that says so, never a fake OK.
	seam = newFakeSeam()
	seam.statusErr = fs.ErrNotExist
	resp = NewActions(seam).UnitStatus(req)
	if resp.OK || resp.Error == "" {
		t.Fatalf("missing unit: %+v", resp)
	}
}

func TestUnitLogsAction(t *testing.T) {
	seam := newFakeSeam()
	seam.logs = []string{"one", "two"}
	req, err := DecodeRequest([]byte(`{"action":"unit-logs","spec":{"slug":"blog"}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp := NewActions(seam).UnitLogs(req)
	if !resp.OK || len(resp.Logs) != 2 {
		t.Fatalf("logs: %+v", resp)
	}
	if seam.logLines != 20 { // unset lines defaults to 20
		t.Errorf("default lines %d", seam.logLines)
	}
	for _, lines := range []int{-1, 600} {
		bad, _ := DecodeRequest([]byte(`{"action":"unit-logs","spec":{"slug":"blog","lines":` + strconv.Itoa(lines) + `}}`))
		if resp := NewActions(seam).UnitLogs(bad); resp.OK {
			t.Errorf("lines %d accepted", lines)
		}
	}
	// A helper failure surfaces as error.
	seam = newFakeSeam()
	seam.logsErr = errors.New("journalctl failed")
	if resp := NewActions(seam).UnitLogs(req); resp.OK || resp.Error == "" {
		t.Fatalf("log failure: %+v", resp)
	}
}
