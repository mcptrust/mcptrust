package version

import (
	"runtime/debug"
)

// readBuildInfo hook
var readBuildInfo = debug.ReadBuildInfo

// BuildVersion getter
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
