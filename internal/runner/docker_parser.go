package runner

import (
	"fmt"
	"strings"
)

// DockerRunArgs parsed options
type DockerRunArgs struct {
	Options  []string // Flags and their values before the image
	Image    string   // The image reference
	Command  []string // Command and args after image
	ImageIdx int      // Position of image in original args (for debugging)
}

// KnownDockerFlags map (conservative list)
var KnownDockerFlags = map[string]bool{
	// Environment
	"-e": true, "--env": true,
	"--env-file": true,
	// Volumes
	"-v": true, "--volume": true,
	"--mount": true,
	"--tmpfs": true,
	// Network
	"-p": true, "--publish": true,
	"--network":  true,
	"--hostname": true, "-h": true,
	"--add-host":    true,
	"--dns":         true,
	"--dns-search":  true,
	"--expose":      true,
	"--ip":          true,
	"--mac-address": true,
	// Container identity
	"--name": true,
	"-l":     true, "--label": true,
	"--label-file": true,
	// User and permissions
	"-u": true, "--user": true,
	"-w": true, "--workdir": true,
	"--group-add": true,
	// Resource limits
	"--cpus":       true,
	"--cpu-shares": true, "-c": true,
	"--memory": true, "-m": true,
	"--memory-swap":  true,
	"--pids-limit":   true,
	"--ulimit":       true,
	"--device":       true,
	"--blkio-weight": true,
	// Security
	"--cap-add":      true,
	"--cap-drop":     true,
	"--security-opt": true,
	"--userns":       true,
	"--cgroupns":     true,
	// Runtime
	"--entrypoint":   true,
	"--restart":      true,
	"--stop-signal":  true,
	"--stop-timeout": true,
	"--platform":     true,
	"--pull":         true,
	"--runtime":      true,
	"--pid":          true,
	"--ipc":          true,
	"--uts":          true,
	// Logging
	"--log-driver": true,
	"--log-opt":    true,
	// Health
	"--health-cmd":          true,
	"--health-interval":     true,
	"--health-retries":      true,
	"--health-timeout":      true,
	"--health-start-period": true,
	// Storage
	"--storage-opt": true,
	"--shm-size":    true,
	// Other
	"--cidfile":   true,
	"--init-path": true,
	"--isolation": true,
}

// KnownDockerBooleanFlags map
var KnownDockerBooleanFlags = map[string]bool{
	// Common boolean flags
	"--rm": true,
	"-d":   true, "--detach": true,
	"-i": true, "--interactive": true,
	"-t": true, "--tty": true,
	"--privileged":       true,
	"--read-only":        true,
	"--init":             true,
	"--sig-proxy":        true,
	"--no-healthcheck":   true,
	"--oom-kill-disable": true,
	"-P":                 true, "--publish-all": true,
}

// ParseDockerRunCommand (fail-closed)
func ParseDockerRunCommand(args []string) (*DockerRunArgs, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("command too short for docker run")
	}

	// Must start with "docker" "run"
	if args[0] != "docker" {
		return nil, fmt.Errorf("not a docker command: starts with %q", args[0])
	}

	if args[1] != "run" {
		return nil, fmt.Errorf("only 'docker run' is supported; got 'docker %s' (docker compose, exec, etc. are not supported)", args[1])
	}

	if len(args) < 3 {
		return nil, fmt.Errorf("docker run requires an image argument")
	}

	result := &DockerRunArgs{}
	afterDoubleHyphen := false

	for i := 2; i < len(args); i++ {
		arg := args[i]

		// Double hyphen signals end of options
		if arg == "--" {
			afterDoubleHyphen = true
			continue
		}

		if afterDoubleHyphen {
			// First arg after -- is IMAGE
			if result.Image == "" {
				result.Image = arg
				result.ImageIdx = i
			} else {
				result.Command = append(result.Command, arg)
			}
			continue
		}

		// Check if it's a flag
		if strings.HasPrefix(arg, "-") {
			result.Options = append(result.Options, arg)

			// Handle --flag=value format - value is already attached
			if strings.Contains(arg, "=") {
				continue
			}

			// Extract flag name for lookup
			flagName := arg
			if strings.HasPrefix(arg, "--") {
				// Long flag
				flagName = arg
			}

			// Check if this flag takes a value
			if KnownDockerFlags[flagName] {
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					i++
					result.Options = append(result.Options, args[i])
				}
			} else if KnownDockerBooleanFlags[flagName] {
				// Boolean flag - no value, continue
			} else if strings.HasPrefix(arg, "--") && !strings.Contains(arg, "=") {
				// FAIL-CLOSED: Unknown long flag without = could take a value
				// We can't safely determine if next token is value or image
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					return nil, fmt.Errorf("unknown docker flag %q with ambiguous next argument\n"+
						"  Cannot safely determine if %q is a flag value or the image\n"+
						"  Supported: docker run [OPTIONS] IMAGE [COMMAND]\n"+
						"  Suggestion: use -- separator: docker run [OPTIONS] -- IMAGE [COMMAND]\n"+
						"  argv: %v", arg, args[i+1], args)
				}
			}
			continue
		}

		// Not a flag - this is the IMAGE
		result.Image = arg
		result.ImageIdx = i

		// Everything after image is command
		if i+1 < len(args) {
			result.Command = args[i+1:]
		}
		break
	}

	if result.Image == "" {
		return nil, fmt.Errorf("could not identify image in docker run command\n"+
			"  Supported: docker run [OPTIONS] IMAGE [COMMAND]\n"+
			"  Suggestion: use -- separator: docker run [OPTIONS] -- IMAGE [COMMAND]\n"+
			"  argv: %v", args)
	}

	return result, nil
}

// ReplaceImage injects pinned ref
func (d *DockerRunArgs) ReplaceImage(pinnedRef string) []string {
	result := []string{"run"}
	result = append(result, d.Options...)
	result = append(result, pinnedRef)
	result = append(result, d.Command...)
	return result
}

// ValidateImageHasDigest matches image@sha256:...
func ValidateImageHasDigest(image string) error {
	if !strings.Contains(image, "@sha256:") {
		if strings.Contains(image, ":") {
			// Has a tag but no digest
			return fmt.Errorf("image %q uses a tag; digest pinning required (use image@sha256:...)", image)
		}
		return fmt.Errorf("image %q has no digest; digest pinning required (use image@sha256:...)", image)
	}
	return nil
}
