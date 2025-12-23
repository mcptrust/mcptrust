// Package artifact provides artifact resolution, pinning, and provenance verification
// for MCP server artifacts (npm packages, OCI images).
package artifact

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/mcptrust/mcptrust/internal/models"
)

var dockerPattern = regexp.MustCompile(`\bdocker\s+run\b`)

func DetectArtifactType(command string) models.ArtifactType {
	command = strings.TrimSpace(command)

	if strings.HasPrefix(command, "npx ") || strings.Contains(command, " npx ") {
		return models.ArtifactTypeNPM
	}

	if dockerPattern.MatchString(command) {
		return models.ArtifactTypeOCI
	}

	return models.ArtifactTypeLocal
}

type NPMPackageRef struct {
	Name    string
	Version string
	Args    string
}

func ParseNPXCommand(command string) (*NPMPackageRef, error) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty command")
	}

	npxIdx := -1
	for i, p := range parts {
		if p == "npx" {
			npxIdx = i
			break
		}
	}

	if npxIdx == -1 {
		return nil, fmt.Errorf("not an npx command")
	}

	var packageSpec string
	var argsStart int
	for i := npxIdx + 1; i < len(parts); i++ {
		p := parts[i]
		// Skip npx flags
		if p == "-y" || p == "--yes" || p == "-q" || p == "--quiet" ||
			p == "-p" || p == "--package" || p == "-c" {
			continue
		}
		// Skip flag values (e.g., --package @scope/pkg)
		if strings.HasPrefix(p, "-") {
			continue
		}
		// This should be the package spec
		packageSpec = p
		argsStart = i + 1
		break
	}

	if packageSpec == "" {
		return nil, fmt.Errorf("could not find package specification in npx command")
	}

	name, version := parsePackageSpec(packageSpec)

	var args string
	if argsStart < len(parts) {
		args = strings.Join(parts[argsStart:], " ")
	}

	return &NPMPackageRef{
		Name:    name,
		Version: version,
		Args:    args,
	}, nil
}

func parsePackageSpec(spec string) (name string, version string) {
	if strings.HasPrefix(spec, "@") {
		restIdx := strings.Index(spec[1:], "@")
		if restIdx == -1 {
			return spec, ""
		}
		atIdx := restIdx + 1
		return spec[:atIdx], spec[atIdx+1:]
	}

	atIdx := strings.LastIndex(spec, "@")
	if atIdx == -1 {
		return spec, ""
	}
	return spec[:atIdx], spec[atIdx+1:]
}

type OCIImageRef struct {
	Registry   string
	Repository string
	Tag        string
	Digest     string
}

func (r *OCIImageRef) String() string {
	var sb strings.Builder

	if r.Registry != "" {
		sb.WriteString(r.Registry)
		sb.WriteString("/")
	}
	sb.WriteString(r.Repository)

	if r.Digest != "" {
		sb.WriteString("@")
		sb.WriteString(r.Digest)
	} else if r.Tag != "" {
		sb.WriteString(":")
		sb.WriteString(r.Tag)
	}

	return sb.String()
}

func ParseOCIReference(ref string) (*OCIImageRef, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("empty image reference")
	}

	result := &OCIImageRef{}

	if atIdx := strings.LastIndex(ref, "@"); atIdx != -1 {
		result.Digest = ref[atIdx+1:]
		ref = ref[:atIdx]
	}

	if colonIdx := strings.LastIndex(ref, ":"); colonIdx != -1 {
		slashIdx := strings.LastIndex(ref, "/")
		if colonIdx > slashIdx {
			result.Tag = ref[colonIdx+1:]
			ref = ref[:colonIdx]
		}
	}

	slashIdx := strings.Index(ref, "/")
	if slashIdx != -1 {
		possibleRegistry := ref[:slashIdx]
		if strings.Contains(possibleRegistry, ".") || strings.Contains(possibleRegistry, ":") {
			result.Registry = possibleRegistry
			ref = ref[slashIdx+1:]
		}
	}

	result.Repository = ref

	if result.Repository == "" {
		return nil, fmt.Errorf("invalid image reference: missing repository")
	}

	return result, nil
}

func ParseDockerCommand(command string) (*OCIImageRef, error) {
	parts := strings.Fields(command)

	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "docker" && parts[i+1] == "run" {
			// Find the image reference (first arg that doesn't start with -)
			for j := i + 2; j < len(parts); j++ {
				arg := parts[j]
				if strings.HasPrefix(arg, "-") {
					if arg == "-v" || arg == "--volume" ||
						arg == "-e" || arg == "--env" ||
						arg == "-p" || arg == "--publish" ||
						arg == "--name" || arg == "--network" {
						j++ // Skip the value
					}
					continue
				}
				return ParseOCIReference(arg)
			}
		}
	}

	return nil, fmt.Errorf("could not find image reference in docker command")
}
