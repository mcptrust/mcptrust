package version

import (
	"runtime/debug"
	"testing"
)

func TestBuildVersion_WithReleaseTag(t *testing.T) {
	original := readBuildInfo
	defer func() { readBuildInfo = original }()

	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{
				Version: "v0.1.0",
			},
		}, true
	}

	got := BuildVersion()
	want := "v0.1.0"
	if got != want {
		t.Errorf("BuildVersion() = %q, want %q", got, want)
	}
}

func TestBuildVersion_Unavailable(t *testing.T) {
	original := readBuildInfo
	defer func() { readBuildInfo = original }()

	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return nil, false
	}

	got := BuildVersion()
	want := "dev"
	if got != want {
		t.Errorf("BuildVersion() = %q, want %q", got, want)
	}
}

func TestBuildVersion_DevelVersion(t *testing.T) {
	original := readBuildInfo
	defer func() { readBuildInfo = original }()

	// (devel) is what go build/run returns
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{
				Version: "(devel)",
			},
		}, true
	}

	got := BuildVersion()
	want := "dev"
	if got != want {
		t.Errorf("BuildVersion() = %q, want %q", got, want)
	}
}

func TestBuildVersion_EmptyVersion(t *testing.T) {
	original := readBuildInfo
	defer func() { readBuildInfo = original }()

	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{
				Version: "",
			},
		}, true
	}

	got := BuildVersion()
	want := "dev"
	if got != want {
		t.Errorf("BuildVersion() = %q, want %q", got, want)
	}
}
