package policy

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/mcptrust/mcptrust/internal/models"
)

// Engine evaluates CEL policies
type Engine struct {
	env *cel.Env
}

func NewEngine() (*Engine, error) {
	env, err := cel.NewEnv(
		cel.Variable("input", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	return &Engine{env: env}, nil
}

// Evaluate rules
func (e *Engine) Evaluate(config *models.PolicyConfig, report *models.ScanReport) ([]models.PolicyResult, error) {
	return e.EvaluateWithLockfile(config, report, nil)
}

// EvaluateWithLockfile with artifact context
func (e *Engine) EvaluateWithLockfile(config *models.PolicyConfig, report *models.ScanReport, lockfile *models.Lockfile) ([]models.PolicyResult, error) {
	results := make([]models.PolicyResult, 0, len(config.Rules))

	// report -> map
	input := reportToMap(report)

	// Add artifact info
	if lockfile != nil && lockfile.Artifact != nil {
		input["artifact"] = artifactToMap(lockfile.Artifact)
		// Only expose verified provenance (SLSA)
		if lockfile.Artifact.Provenance != nil &&
			lockfile.Artifact.Provenance.Method == models.ProvenanceMethodCosignSLSA {
			input["provenance"] = provenanceToMap(lockfile.Artifact.Provenance)
		}
	}

	for _, rule := range config.Rules {
		result, err := e.evaluateRule(rule, input)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate rule %q: %w", rule.Name, err)
		}
		results = append(results, result)
	}

	return results, nil
}

// EvaluateWithV3Input extended checks
func (e *Engine) EvaluateWithV3Input(config *models.PolicyConfig, policyInput *V3PolicyInput) ([]models.PolicyResult, error) {
	results := make([]models.PolicyResult, 0, len(config.Rules))

	input := policyInput.ToMap()

	for _, rule := range config.Rules {
		result, err := e.evaluateRule(rule, input)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate rule %q: %w", rule.Name, err)
		}
		results = append(results, result)
	}

	return results, nil
}

// evaluateRule with cost limits (SEC-02 prevention)
func (e *Engine) evaluateRule(rule models.PolicyRule, input map[string]interface{}) (models.PolicyResult, error) {
	// Default severity: error
	severity := rule.Severity
	if severity == "" {
		severity = models.PolicySeverityError
	}

	// Compile
	ast, issues := e.env.Compile(rule.Expr)
	if issues != nil && issues.Err() != nil {
		return models.PolicyResult{
			RuleName:   rule.Name,
			Passed:     false,
			FailureMsg: fmt.Sprintf("CEL compile error: %v", issues.Err()),
			Severity:   severity,
		}, nil
	}

	// SEC-02: Enforce cost limit
	// MaxCELCost is a defensive limit - most policies use <10,000 cost.
	const MaxCELCost = 1_000_000

	prg, err := e.env.Program(ast, cel.CostLimit(MaxCELCost))
	if err != nil {
		return models.PolicyResult{
			RuleName:   rule.Name,
			Passed:     false,
			FailureMsg: fmt.Sprintf("CEL program error: %v", err),
			Severity:   severity,
		}, nil
	}

	// Eval
	out, _, err := prg.Eval(map[string]interface{}{
		"input": input,
	})
	if err != nil {
		return models.PolicyResult{
			RuleName:   rule.Name,
			Passed:     false,
			FailureMsg: fmt.Sprintf("CEL evaluation error: %v", err),
			Severity:   severity,
		}, nil
	}

	// Check boolean
	passed, ok := out.Value().(bool)
	if !ok {
		return models.PolicyResult{
			RuleName:   rule.Name,
			Passed:     false,
			FailureMsg: fmt.Sprintf("Rule expression must return boolean, got %T", out.Value()),
			Severity:   severity,
		}, nil
	}

	result := models.PolicyResult{
		RuleName: rule.Name,
		Passed:   passed,
		Severity: severity,
	}
	if !passed {
		result.FailureMsg = rule.FailureMsg
	}

	return result, nil
}

// reportToMap -> cel
func reportToMap(report *models.ScanReport) map[string]interface{} {
	tools := make([]interface{}, len(report.Tools))
	for i, t := range report.Tools {
		tools[i] = toolToMap(t)
	}

	resources := make([]interface{}, len(report.Resources))
	for i, r := range report.Resources {
		resources[i] = resourceToMap(r)
	}

	result := map[string]interface{}{
		"command":   report.Command,
		"tools":     tools,
		"resources": resources,
		"error":     report.Error,
	}

	if report.ServerInfo != nil {
		result["server_info"] = map[string]interface{}{
			"name":             report.ServerInfo.Name,
			"version":          report.ServerInfo.Version,
			"protocol_version": report.ServerInfo.ProtocolVersion,
		}
	}

	return result
}

func toolToMap(tool models.Tool) map[string]interface{} {
	return map[string]interface{}{
		"name":         tool.Name,
		"description":  tool.Description,
		"input_schema": tool.InputSchema,
		"risk_level":   string(tool.RiskLevel),
		"risk_reasons": stringSliceToInterface(tool.RiskReasons),
	}
}

func resourceToMap(resource models.Resource) map[string]interface{} {
	return map[string]interface{}{
		"uri":         resource.URI,
		"name":        resource.Name,
		"description": resource.Description,
		"mime_type":   resource.MimeType,
	}
}

func stringSliceToInterface(s []string) []interface{} {
	result := make([]interface{}, len(s))
	for i, v := range s {
		result[i] = v
	}
	return result
}

// artifactToMap helper
func artifactToMap(artifact *models.ArtifactPin) map[string]interface{} {
	if artifact == nil {
		return nil
	}
	result := map[string]interface{}{
		"type":      string(artifact.Type),
		"name":      artifact.Name,
		"version":   artifact.Version,
		"registry":  artifact.Registry,
		"integrity": artifact.Integrity,
		"image":     artifact.Image,
		"digest":    artifact.Digest,
	}
	if artifact.Provenance != nil {
		result["provenance"] = provenanceToMap(artifact.Provenance)
	}
	return result
}

// provenanceToMap helper
func provenanceToMap(prov *models.ProvenanceInfo) map[string]interface{} {
	if prov == nil {
		return nil
	}
	return map[string]interface{}{
		// Disambiguate verification
		"method": string(prov.Method),
		// Raw fields
		"predicate_type": prov.PredicateType,
		"builder_id":     prov.BuilderID,
		"source_repo":    prov.SourceRepo,
		"source_ref":     prov.SourceRef,
		"workflow_uri":   prov.WorkflowURI,
		"issuer":         prov.Issuer,
		"identity":       prov.Identity,
		"verified":       prov.Verified,
		"verified_at":    prov.VerifiedAt,
		// Aliases
		"config_source_uri":        prov.SourceRepo,  // alias
		"config_source_entrypoint": prov.WorkflowURI, // alias
	}
}

// CompileAndValidate rules
func (e *Engine) CompileAndValidate(config *models.PolicyConfig) error {
	var errors []string

	for _, rule := range config.Rules {
		_, issues := e.env.Compile(rule.Expr)
		if issues != nil && issues.Err() != nil {
			errors = append(errors, fmt.Sprintf("rule %q: %v", rule.Name, issues.Err()))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("policy validation failed:\n  %s", strings.Join(errors, "\n  "))
	}

	return nil
}
