package models

// PolicyConfig from yaml
type PolicyConfig struct {
	Name  string       `yaml:"name"`
	Rules []PolicyRule `yaml:"rules"`
}

// PolicyRule cel rule
type PolicyRule struct {
	Name       string `yaml:"name"`
	Expr       string `yaml:"expr"`
	FailureMsg string `yaml:"failure_msg"`
}

// PolicyResult eval result
type PolicyResult struct {
	RuleName   string
	Passed     bool
	FailureMsg string
}
