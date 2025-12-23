package artifact

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/mcptrust/mcptrust/internal/models"
)

type OCIProvenanceResult struct {
	Verified       bool
	VerifiedAt     time.Time
	ProvenanceInfo *models.ProvenanceInfo
	RawStatement   json.RawMessage
	Error          error
}

func ResolveOCIDigest(ctx context.Context, imageRef string) (string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("failed to parse image reference: %w", err)
	}

	digest, err := crane.Digest(ref.String())
	if err != nil {
		return "", fmt.Errorf("failed to resolve digest: %w", err)
	}

	return digest, nil
}

func CreateOCIPin(ctx context.Context, imageRef *OCIImageRef) (*models.ArtifactPin, error) {
	pin := &models.ArtifactPin{
		Type: models.ArtifactTypeOCI,
	}

	if imageRef.Registry != "" {
		pin.Image = imageRef.Registry + "/" + imageRef.Repository
	} else {
		pin.Image = imageRef.Repository
	}

	if imageRef.Digest != "" {
		pin.Digest = imageRef.Digest
		return pin, nil
	}

	refStr := pin.Image
	if imageRef.Tag != "" {
		refStr = refStr + ":" + imageRef.Tag
	}

	digest, err := ResolveOCIDigest(ctx, refStr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve image digest: %w", err)
	}

	pin.Digest = digest
	return pin, nil
}

func VerifyOCIProvenance(ctx context.Context, pin *models.ArtifactPin, expectedSource string) (*OCIProvenanceResult, error) {
	if pin.Type != models.ArtifactTypeOCI {
		return nil, fmt.Errorf("artifact is not an OCI image")
	}

	if pin.Digest == "" {
		return nil, fmt.Errorf("OCI pin must have a digest for provenance verification")
	}

	if !isCosignAvailable(ctx) {
		return nil, fmt.Errorf("cosign not found in PATH (required for OCI provenance verification)")
	}

	imageRefWithDigest := pin.Image + "@" + pin.Digest

	identityRegex := ".*"
	if expectedSource != "" {
		identityRegex = expectedSource + ".*"
	}

	args := []string{
		"verify-attestation",
		"--type", "slsaprovenance",
		"--output", "json",
		"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
		"--certificate-identity-regexp", identityRegex,
		imageRefWithDigest,
	}

	stdout, stderr, err := runCommand(ctx, "cosign", args, nil)
	if err != nil {
		return &OCIProvenanceResult{
			Verified: false,
			Error:    fmt.Errorf("cosign verification failed: %s %s", string(stdout), string(stderr)),
		}, nil
	}

	provenanceInfo, rawStatement, err := parseOCICosignOutput(stdout, expectedSource)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cosign output: %w", err)
	}

	provenanceInfo.Method = models.ProvenanceMethodCosignSLSA
	provenanceInfo.Verified = true
	provenanceInfo.VerifiedAt = time.Now().UTC().Format(time.RFC3339)

	return &OCIProvenanceResult{
		Verified:       true,
		VerifiedAt:     time.Now().UTC(),
		ProvenanceInfo: provenanceInfo,
		RawStatement:   rawStatement,
	}, nil
}

type CosignVerifyOutput struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"` // base64 encoded
}

func parseOCICosignOutput(output []byte, expectedSource string) (*models.ProvenanceInfo, json.RawMessage, error) {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		var cosignOutput CosignVerifyOutput
		if err := json.Unmarshal([]byte(line), &cosignOutput); err != nil {
			var envelope DSSEEnvelope
			if err2 := json.Unmarshal([]byte(line), &envelope); err2 != nil {
				continue
			}
			cosignOutput.Payload = envelope.Payload
		}

		if cosignOutput.Payload == "" {
			continue
		}

		payloadBytes, err := base64.StdEncoding.DecodeString(cosignOutput.Payload)
		if err != nil {
			continue
		}

		var statement InTotoStatement
		if err := json.Unmarshal(payloadBytes, &statement); err != nil {
			continue
		}

		if !strings.HasPrefix(statement.PredicateType, "https://slsa.dev/provenance") {
			continue
		}

		info, rawStatement, err := parseInTotoStatement(payloadBytes, expectedSource)
		if err != nil {
			continue
		}

		return info, rawStatement, nil
	}

	return nil, nil, fmt.Errorf("no SLSA provenance attestation found in cosign output")
}

func VerifyOCIIntegrity(ctx context.Context, pin *models.ArtifactPin) error {
	if pin.Type != models.ArtifactTypeOCI {
		return fmt.Errorf("artifact is not an OCI image")
	}

	if pin.Digest == "" {
		return fmt.Errorf("OCI pin has no digest to verify")
	}

	// Build image reference (without digest, to get current state)
	// If we have a tag stored, use it; otherwise just use the image name
	// This is a limitation - we need some way to re-resolve the image

	// For now, we verify that the digest is still valid by checking it exists
	imageRefWithDigest := pin.Image + "@" + pin.Digest

	_, err := crane.Manifest(imageRefWithDigest)
	if err != nil {
		return fmt.Errorf("digest verification failed: %w", err)
	}

	return nil
}

func GetCanonicalOCIReference(pin *models.ArtifactPin) string {
	if pin.Type != models.ArtifactTypeOCI {
		return ""
	}
	if pin.Digest == "" {
		return pin.Image
	}
	return pin.Image + "@" + pin.Digest
}
