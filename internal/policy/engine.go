package policy

import (
	"fmt"
	"strings"

	"github.com/dtang19/mcptrust/internal/models"
	"github.com/google/cel-go/cel"
)

// Engine is the policy evaluation engine using CEL
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

// Evaluate checks rules
func (e *Engine) Evaluate(config *models.PolicyConfig, report *models.ScanReport) ([]models.PolicyResult, error) {
	results := make([]models.PolicyResult, 0, len(config.Rules))

	// convert report
	input := reportToMap(report)

	for _, rule := range config.Rules {
		result, err := e.evaluateRule(rule, input)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate rule %q: %w", rule.Name, err)
		}
		results = append(results, result)
	}

	return results, nil
}

// evaluateRule
func (e *Engine) evaluateRule(rule models.PolicyRule, input map[string]interface{}) (models.PolicyResult, error) {
	// compile
	ast, issues := e.env.Compile(rule.Expr)
	if issues != nil && issues.Err() != nil {
		return models.PolicyResult{
			RuleName:   rule.Name,
			Passed:     false,
			FailureMsg: fmt.Sprintf("CEL compile error: %v", issues.Err()),
		}, nil
	}

	// program
	prg, err := e.env.Program(ast)
	if err != nil {
		return models.PolicyResult{
			RuleName:   rule.Name,
			Passed:     false,
			FailureMsg: fmt.Sprintf("CEL program error: %v", err),
		}, nil
	}

	// eval
	out, _, err := prg.Eval(map[string]interface{}{
		"input": input,
	})
	if err != nil {
		return models.PolicyResult{
			RuleName:   rule.Name,
			Passed:     false,
			FailureMsg: fmt.Sprintf("CEL evaluation error: %v", err),
		}, nil
	}

	// check bool
	passed, ok := out.Value().(bool)
	if !ok {
		return models.PolicyResult{
			RuleName:   rule.Name,
			Passed:     false,
			FailureMsg: fmt.Sprintf("Rule expression must return boolean, got %T", out.Value()),
		}, nil
	}

	result := models.PolicyResult{
		RuleName: rule.Name,
		Passed:   passed,
	}
	if !passed {
		result.FailureMsg = rule.FailureMsg
	}

	return result, nil
}

// reportToMap converts for CEL
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

// toolToMap
func toolToMap(tool models.Tool) map[string]interface{} {
	return map[string]interface{}{
		"name":         tool.Name,
		"description":  tool.Description,
		"input_schema": tool.InputSchema,
		"risk_level":   string(tool.RiskLevel),
		"risk_reasons": stringSliceToInterface(tool.RiskReasons),
	}
}

// resourceToMap
func resourceToMap(resource models.Resource) map[string]interface{} {
	return map[string]interface{}{
		"uri":         resource.URI,
		"name":        resource.Name,
		"description": resource.Description,
		"mime_type":   resource.MimeType,
	}
}

// stringSliceToInterface
func stringSliceToInterface(s []string) []interface{} {
	result := make([]interface{}, len(s))
	for i, v := range s {
		result[i] = v
	}
	return result
}

// CompileAndValidate
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
