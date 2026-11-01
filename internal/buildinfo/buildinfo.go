// Package buildinfo holds what the build stamps into the binary.
package buildinfo

// Version is set with -ldflags "-X .../buildinfo.Version=X.Y.Z" (make build); "dev" is any other build.
var Version = "dev"
