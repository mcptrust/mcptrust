package version

import (
	"runtime/debug"
)

// Swappable for testing
var readBuildInfo = debug.ReadBuildInfo

// BuildVersion returns the module version, or "dev" if unavailable.
func BuildVersion() string {
	info, ok := readBuildInfo()
	if !ok {
		return "dev"
	}
	if info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "dev"
	}
	return info.Main.Version
}
