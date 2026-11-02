package web

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Every server the tests build hashes the admin password and every login compares one; at the production cost that
// was most of the suite's time under -race. The cost is only a work factor, so behavior is unchanged.
func TestMain(m *testing.M) {
	bcryptCost = bcrypt.MinCost
	os.Exit(m.Run())
}
