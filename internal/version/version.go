// Package version holds build metadata for the correlator binary.
package version

import "runtime"

// Version is the correlator release version.
const Version = "2.0.1"

// String returns a one-line version summary including platform.
func String() string {
	return "correlator " + Version + " (" + runtime.GOOS + "/" + runtime.GOARCH + ")"
}
