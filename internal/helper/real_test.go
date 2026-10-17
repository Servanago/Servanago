package helper

import "testing"

// Editing or toggling a site calls user-add again: an existing user is success, not a useradd error.
// "root" always exists, so this never runs useradd on the test host.
func TestRealSeamUserAddIsIdempotent(t *testing.T) {
	if err := (RealSeam{}).UserAdd("root", "/root"); err != nil {
		t.Fatalf("existing user: %v", err)
	}
}
