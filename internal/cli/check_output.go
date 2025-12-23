package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/mcptrust/mcptrust/internal/differ"
	"github.com/mcptrust/mcptrust/internal/models"
)

// FailOnLevel threshold for failure
type FailOnLevel string

const (
	FailOnCritical FailOnLevel = "critical"
	FailOnModerate FailOnLevel = "moderate"
	FailOnInfo     FailOnLevel = "info"
)

// ParseFailOnLevel from string
func ParseFailOnLevel(s string) (FailOnLevel, error) {
	switch strings.ToLower(s) {
	case "critical":
		return FailOnCritical, nil
	case "moderate":
		return FailOnModerate, nil
	case "info":
		return FailOnInfo, nil
	default:
		return "", fmt.Errorf("invalid fail-on level: %s (use critical, moderate, or info)", s)
	}
}

// ShouldFail checks limits
func (f FailOnLevel) ShouldFail(severity differ.SeverityLevel) bool {
	switch f {
	case FailOnCritical:
		return severity == differ.SeverityCritical
	case FailOnModerate:
		return severity >= differ.SeverityModerate
	case FailOnInfo:
		return true // all severities fail
	default:
		return severity == differ.SeverityCritical
	}
}

// CheckResult output structure
type CheckResult struct {
	LockfileVersion string            `json:"lockfileVersion"`
	Server          string            `json:"server"`
	LockfilePath    string            `json:"lockfile"`
	Summary         CheckSummary      `json:"summary"`
	Drift           []DriftOutputItem `json:"drift"`
	Policy          *PolicyDecision   `json:"policy,omitempty"`
	FailOn          string            `json:"failOn"`
	Outcome         string            `json:"outcome"` // "PASS" or "FAIL"
}

// CheckSummary by severity
type CheckSummary struct {
	Critical int `json:"critical"`
	Moderate int `json:"moderate"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// DriftOutputItem detail
type DriftOutputItem struct {
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	Identifier string `json:"identifier"`
	OldHash    string `json:"oldHash,omitempty"`
	NewHash    string `json:"newHash,omitempty"`
	Message    string `json:"message"`
}

// PolicyDecision result
type PolicyDecision struct {
	Preset  string   `json:"preset"`
	Passed  bool     `json:"passed"`
	Reasons []string `json:"reasons,omitempty"`
}

// BuildCheckResult from components
func BuildCheckResult(
	lockfileVersion string,
	serverName string,
	lockfilePath string,
	drift *differ.V3Result,
	policyResults []models.PolicyResult,
	policyPreset string,
	failOn FailOnLevel,
) *CheckResult {
	result := &CheckResult{
		LockfileVersion: lockfileVersion,
		Server:          serverName,
		LockfilePath:    lockfilePath,
		Drift:           []DriftOutputItem{},
		FailOn:          string(failOn),
		Outcome:         "PASS",
	}

	// Build drift items
	if drift != nil && len(drift.Drifts) > 0 {
		for _, d := range drift.Drifts {
			result.Drift = append(result.Drift, DriftOutputItem{
				Type:       string(d.Type),
				Severity:   differ.SeverityString(d.Severity),
				Identifier: d.Identifier,
				OldHash:    d.OldHash,
				NewHash:    d.NewHash,
				Message:    d.Message,
			})
		}
	}

	// Calculate summary
	result.Summary = calculateSummary(drift)

	// Build policy decision
	if len(policyResults) > 0 {
		decision := &PolicyDecision{
			Preset: policyPreset,
			Passed: true,
		}

		for _, pr := range policyResults {
			if !pr.Passed && pr.Severity == models.PolicySeverityError {
				decision.Passed = false
				decision.Reasons = append(decision.Reasons, fmt.Sprintf("%s: %s", pr.RuleName, pr.FailureMsg))
			}
		}

		result.Policy = decision
	}

	// Determine outcome
	if result.Policy != nil && !result.Policy.Passed {
		result.Outcome = "FAIL"
	} else if shouldFailOnDrift(drift, failOn) {
		result.Outcome = "FAIL"
	}

	return result
}

// calculateSummary counts
func calculateSummary(drift *differ.V3Result) CheckSummary {
	summary := CheckSummary{}
	if drift == nil {
		return summary
	}

	for _, d := range drift.Drifts {
		switch d.Severity {
		case differ.SeverityCritical:
			summary.Critical++
		case differ.SeverityModerate:
			summary.Moderate++
		default:
			summary.Info++
		}
		summary.Total++
	}

	return summary
}

// shouldFailOnDrift checks threshold
func shouldFailOnDrift(drift *differ.V3Result, failOn FailOnLevel) bool {
	if drift == nil || !drift.HasDrift {
		return false
	}

	for _, d := range drift.Drifts {
		if failOn.ShouldFail(d.Severity) {
			return true
		}
	}

	return false
}

// FormatTextOutput human readable
func FormatTextOutput(result *CheckResult) string {
	var sb strings.Builder

	// Header with outcome
	policyName := "none"
	if result.Policy != nil {
		policyName = result.Policy.Preset
	}

	if result.Outcome == "PASS" {
		sb.WriteString(fmt.Sprintf("%sMCPTrust check: PASS%s (policy=%s, fail-on=%s)\n",
			colorGreen, colorReset, policyName, result.FailOn))
	} else {
		sb.WriteString(fmt.Sprintf("%sMCPTrust check: FAIL%s (policy=%s, fail-on=%s)\n",
			colorRed, colorReset, policyName, result.FailOn))
	}

	sb.WriteString(fmt.Sprintf("Server: %s\n", result.Server))
	sb.WriteString(fmt.Sprintf("Lockfile: %s (v%s)\n", result.LockfilePath, result.LockfileVersion))
	sb.WriteString("\n")

	// Drift items grouped by severity
	if result.Summary.Total > 0 {
		// Group by severity
		groups := groupDriftBySeverity(result.Drift)

		if len(groups["critical"]) > 0 {
			sb.WriteString(fmt.Sprintf("%sCRITICAL (%d)%s\n", colorRed, len(groups["critical"]), colorReset))
			for _, d := range groups["critical"] {
				formatDriftItem(&sb, d, colorRed)
			}
			sb.WriteString("\n")
		}

		if len(groups["moderate"]) > 0 {
			sb.WriteString(fmt.Sprintf("%sMODERATE (%d)%s\n", colorYellow, len(groups["moderate"]), colorReset))
			for _, d := range groups["moderate"] {
				formatDriftItem(&sb, d, colorYellow)
			}
			sb.WriteString("\n")
		}

		if len(groups["info"]) > 0 {
			sb.WriteString(fmt.Sprintf("INFO (%d)\n", len(groups["info"])))
			for _, d := range groups["info"] {
				formatDriftItem(&sb, d, "")
			}
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString(fmt.Sprintf("%s✓ No drift detected%s\n\n", colorGreen, colorReset))
	}

	// Policy decision
	if result.Policy != nil {
		if result.Policy.Passed {
			sb.WriteString(fmt.Sprintf("Policy: %sPASS%s\n", colorGreen, colorReset))
		} else {
			sb.WriteString(fmt.Sprintf("Policy: %sDENY%s\n", colorRed, colorReset))
			for _, reason := range result.Policy.Reasons {
				sb.WriteString(fmt.Sprintf("- %s\n", reason))
			}
		}
	}

	return sb.String()
}

// groupDriftBySeverity helper
func groupDriftBySeverity(drifts []DriftOutputItem) map[string][]DriftOutputItem {
	groups := map[string][]DriftOutputItem{
		"critical": {},
		"moderate": {},
		"info":     {},
	}

	for _, d := range drifts {
		groups[d.Severity] = append(groups[d.Severity], d)
	}

	// Sort each group by identifier for deterministic output
	for k := range groups {
		sort.Slice(groups[k], func(i, j int) bool {
			return groups[k][i].Identifier < groups[k][j].Identifier
		})
	}

	return groups
}

func formatDriftItem(sb *strings.Builder, d DriftOutputItem, color string) {
	if color != "" {
		sb.WriteString(fmt.Sprintf("%s- %s: %s%s\n", color, d.Type, d.Identifier, colorReset))
	} else {
		sb.WriteString(fmt.Sprintf("- %s: %s\n", d.Type, d.Identifier))
	}

	if d.OldHash != "" && d.NewHash != "" {
		sb.WriteString(fmt.Sprintf("    %s → %s\n", truncHashOutput(d.OldHash), truncHashOutput(d.NewHash)))
	}
}

// truncHashOutput shortener
func truncHashOutput(h string) string {
	if len(h) <= 16 {
		return h
	}
	return h[:16] + "..."
}

// FormatJSONOutput raw json
func FormatJSONOutput(result *CheckResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}
