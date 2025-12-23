package artifact

import (
	"testing"

	"github.com/mcptrust/mcptrust/internal/models"
)

func TestDetectArtifactType(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		expected models.ArtifactType
	}{
		{
			name:     "npx command",
			command:  "npx -y @modelcontextprotocol/server-filesystem /tmp",
			expected: models.ArtifactTypeNPM,
		},
		{
			name:     "npx without flags",
			command:  "npx @scope/package",
			expected: models.ArtifactTypeNPM,
		},
		{
			name:     "docker run",
			command:  "docker run -v /data:/data ghcr.io/org/server:v1",
			expected: models.ArtifactTypeOCI,
		},
		{
			name:     "python script",
			command:  "python mcp_server.py",
			expected: models.ArtifactTypeLocal,
		},
		{
			name:     "local binary",
			command:  "./my-server --port 8080",
			expected: models.ArtifactTypeLocal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectArtifactType(tt.command)
			if result != tt.expected {
				t.Errorf("DetectArtifactType(%q) = %q, want %q", tt.command, result, tt.expected)
			}
		})
	}
}

func TestParseNPXCommand(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		wantName    string
		wantVersion string
		wantArgs    string
		wantErr     bool
	}{
		{
			name:        "scoped package with -y flag",
			command:     "npx -y @modelcontextprotocol/server-filesystem /tmp",
			wantName:    "@modelcontextprotocol/server-filesystem",
			wantVersion: "",
			wantArgs:    "/tmp",
		},
		{
			name:        "scoped package with version",
			command:     "npx -y @scope/package@1.2.3 --flag value",
			wantName:    "@scope/package",
			wantVersion: "1.2.3",
			wantArgs:    "--flag value",
		},
		{
			name:        "unscoped package",
			command:     "npx cowsay hello",
			wantName:    "cowsay",
			wantVersion: "",
			wantArgs:    "hello",
		},
		{
			name:        "unscoped package with version",
			command:     "npx create-react-app@5.0.0 my-app",
			wantName:    "create-react-app",
			wantVersion: "5.0.0",
			wantArgs:    "my-app",
		},
		{
			name:    "not an npx command",
			command: "node server.js",
			wantErr: true,
		},
		{
			name:    "empty command",
			command: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := ParseNPXCommand(tt.command)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseNPXCommand(%q) expected error, got nil", tt.command)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseNPXCommand(%q) unexpected error: %v", tt.command, err)
				return
			}

			if ref.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", ref.Name, tt.wantName)
			}
			if ref.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", ref.Version, tt.wantVersion)
			}
			if ref.Args != tt.wantArgs {
				t.Errorf("Args = %q, want %q", ref.Args, tt.wantArgs)
			}
		})
	}
}

func TestParsePackageSpec(t *testing.T) {
	tests := []struct {
		spec        string
		wantName    string
		wantVersion string
	}{
		{"package", "package", ""},
		{"package@1.0.0", "package", "1.0.0"},
		{"@scope/package", "@scope/package", ""},
		{"@scope/package@2.1.0", "@scope/package", "2.1.0"},
		{"@scope/package@next", "@scope/package", "next"},
	}

	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			name, version := parsePackageSpec(tt.spec)
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
		})
	}
}

func TestParseOCIReference(t *testing.T) {
	tests := []struct {
		name       string
		ref        string
		wantReg    string
		wantRepo   string
		wantTag    string
		wantDigest string
		wantErr    bool
	}{
		{
			name:     "simple image with tag",
			ref:      "nginx:1.21",
			wantRepo: "nginx",
			wantTag:  "1.21",
		},
		{
			name:     "image with registry and tag",
			ref:      "ghcr.io/org/image:v1.0",
			wantReg:  "ghcr.io",
			wantRepo: "org/image",
			wantTag:  "v1.0",
		},
		{
			name:       "image with digest",
			ref:        "ghcr.io/org/image@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			wantReg:    "ghcr.io",
			wantRepo:   "org/image",
			wantDigest: "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
		},
		{
			name:     "registry with port",
			ref:      "localhost:5000/myimage:latest",
			wantReg:  "localhost:5000",
			wantRepo: "myimage",
			wantTag:  "latest",
		},
		{
			name:    "empty reference",
			ref:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseOCIReference(tt.ref)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseOCIReference(%q) expected error, got nil", tt.ref)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseOCIReference(%q) unexpected error: %v", tt.ref, err)
				return
			}

			if result.Registry != tt.wantReg {
				t.Errorf("Registry = %q, want %q", result.Registry, tt.wantReg)
			}
			if result.Repository != tt.wantRepo {
				t.Errorf("Repository = %q, want %q", result.Repository, tt.wantRepo)
			}
			if result.Tag != tt.wantTag {
				t.Errorf("Tag = %q, want %q", result.Tag, tt.wantTag)
			}
			if result.Digest != tt.wantDigest {
				t.Errorf("Digest = %q, want %q", result.Digest, tt.wantDigest)
			}
		})
	}
}

func TestParseDockerCommand(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		wantRepo string
		wantTag  string
		wantErr  bool
	}{
		{
			name:     "simple docker run",
			command:  "docker run nginx:1.21",
			wantRepo: "nginx",
			wantTag:  "1.21",
		},
		{
			name:     "docker run with flags",
			command:  "docker run -d -p 8080:80 --name web ghcr.io/org/server:v1",
			wantRepo: "org/server",
			wantTag:  "v1",
		},
		{
			name:     "docker run with volume",
			command:  "docker run -v /data:/data myimage",
			wantRepo: "myimage",
		},
		{
			name:    "not a docker command",
			command: "podman run nginx",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseDockerCommand(tt.command)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseDockerCommand(%q) expected error, got nil", tt.command)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseDockerCommand(%q) unexpected error: %v", tt.command, err)
				return
			}

			if result.Repository != tt.wantRepo {
				t.Errorf("Repository = %q, want %q", result.Repository, tt.wantRepo)
			}
			if result.Tag != tt.wantTag {
				t.Errorf("Tag = %q, want %q", result.Tag, tt.wantTag)
			}
		})
	}
}

func TestIsValidDigest(t *testing.T) {
	tests := []struct {
		digest string
		valid  bool
	}{
		{"sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234", true},
		{"sha256:ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234", true},
		{"sha256:abc", false},      // too short
		{"md5:abcd1234", false},    // wrong algorithm
		{"tag:v1.0", false},        // not a digest
		{"sha256:ghijklmn", false}, // invalid hex chars
	}

	for _, tt := range tests {
		t.Run(tt.digest, func(t *testing.T) {
			result := isValidDigest(tt.digest)
			if result != tt.valid {
				t.Errorf("isValidDigest(%q) = %v, want %v", tt.digest, result, tt.valid)
			}
		})
	}
}
