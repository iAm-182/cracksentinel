// Package version exposes the build identity of the scanner.
//
// The values are overridable at link time so a release build can carry its
// own number without a source edit:
//
//	go build -ldflags "-X gamecrack-scanner/internal/version.Version=1.2.0"
package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the semantic version of the build.
	Version = "1.0.0-dev"
	// Commit is the git commit the build came from (set at link time).
	Commit = "unknown"
	// BuildDate is the build timestamp (set at link time).
	BuildDate = "unknown"
)

// String renders the full build identity.
func String() string {
	return fmt.Sprintf("CrackSentinel %s (commit %s, built %s, %s/%s)",
		Version, Commit, BuildDate, runtime.GOOS, runtime.GOARCH)
}

// Short returns just the version number.
func Short() string { return Version }
