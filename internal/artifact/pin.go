package artifact

import (
	"context"
	"fmt"

	"github.com/mcptrust/mcptrust/internal/models"
)

// CreatePin from command
func CreatePin(ctx context.Context, command string) (*models.ArtifactPin, error) {
	artifactType := DetectArtifactType(command)

	switch artifactType {
	case models.ArtifactTypeNPM:
		return createNPMPinFromCommand(ctx, command)
	case models.ArtifactTypeOCI:
		return createOCIPinFromCommand(ctx, command)
	case models.ArtifactTypeLocal:
		// Local artifacts cannot be pinned
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown artifact type: %s", artifactType)
	}
}

// createNPMPinFromCommand factory
func createNPMPinFromCommand(ctx context.Context, command string) (*models.ArtifactPin, error) {
	ref, err := ParseNPXCommand(command)
	if err != nil {
		return nil, fmt.Errorf("failed to parse npx command: %w", err)
	}

	client := NewNPMClient("")
	return client.CreateNPMPin(ctx, ref)
}

// createOCIPinFromCommand factory
func createOCIPinFromCommand(ctx context.Context, command string) (*models.ArtifactPin, error) {
	imageRef, err := ParseDockerCommand(command)
	if err != nil {
		return nil, fmt.Errorf("failed to parse docker command: %w", err)
	}

	// Use the new CreateOCIPin which properly resolves digests
	return CreateOCIPin(ctx, imageRef)
}

// VerifyPin check
func VerifyPin(ctx context.Context, pin *models.ArtifactPin) error {
	if pin == nil {
		return fmt.Errorf("no artifact pin to verify")
	}

	switch pin.Type {
	case models.ArtifactTypeNPM:
		client := NewNPMClient(pin.Registry)
		return client.VerifyNPMIntegrity(ctx, pin)
	case models.ArtifactTypeOCI:
		return VerifyOCIIntegrity(ctx, pin)
	case models.ArtifactTypeLocal:
		return fmt.Errorf("local artifacts cannot be verified")
	default:
		return fmt.Errorf("unknown artifact type: %s", pin.Type)
	}
}

// VerifyProvenance check
func VerifyProvenance(ctx context.Context, pin *models.ArtifactPin, expectedSource string) (*models.ProvenanceInfo, error) {
	if pin == nil {
		return nil, fmt.Errorf("no artifact pin to verify")
	}

	switch pin.Type {
	case models.ArtifactTypeNPM:
		result, err := VerifyNPMProvenance(ctx, pin, expectedSource)
		if err != nil {
			return nil, err
		}
		if !result.Verified {
			return nil, result.Error
		}
		return result.ProvenanceInfo, nil

	case models.ArtifactTypeOCI:
		result, err := VerifyOCIProvenance(ctx, pin, expectedSource)
		if err != nil {
			return nil, err
		}
		if !result.Verified {
			return nil, result.Error
		}
		return result.ProvenanceInfo, nil

	case models.ArtifactTypeLocal:
		return nil, fmt.Errorf("local artifacts do not have provenance")

	default:
		return nil, fmt.Errorf("unknown artifact type: %s", pin.Type)
	}
}

// isValidDigest checks if a string is a valid OCI digest
func isValidDigest(digest string) bool {
	if len(digest) != 71 { // "sha256:" + 64 hex chars
		return false
	}
	if digest[:7] != "sha256:" {
		return false
	}
	for _, c := range digest[7:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
