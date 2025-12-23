package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/mcptrust/mcptrust/internal/differ"
	"github.com/mcptrust/mcptrust/internal/locker"
	"github.com/mcptrust/mcptrust/internal/models"
	"github.com/mcptrust/mcptrust/internal/policy"
	"github.com/mcptrust/mcptrust/internal/scanner"
)

type Config struct {
	LockfilePath         string
	Timeout              time.Duration
	FailOn               string // "critical", "moderate", "info"
	PolicyPreset         string
	AuditOnly            bool // log but don't filter or block
	FilterOnly           bool // filter lists but don't block calls/reads
	AllowStaticResources bool
}

type Proxy struct {
	cfg        Config
	lockfile   *models.LockfileV3
	enforcer   *Enforcer
	auditOnly  bool
	filterOnly bool
}

func New(cfg Config) (*Proxy, error) {
	mgr := locker.NewManager()

	version, err := mgr.DetectLockfileVersion(cfg.LockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to detect lockfile version: %w", err)
	}
	if version != models.LockfileV3Version {
		return nil, fmt.Errorf("proxy requires lockfile v3, got %s", version)
	}

	lockfile, err := mgr.LoadV3(cfg.LockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load v3 lockfile: %w", err)
	}

	enforcer, err := NewEnforcer(lockfile, cfg.AllowStaticResources)
	if err != nil {
		return nil, fmt.Errorf("failed to create enforcer: %w", err)
	}

	return &Proxy{
		cfg:        cfg,
		lockfile:   lockfile,
		enforcer:   enforcer,
		auditOnly:  cfg.AuditOnly,
		filterOnly: cfg.FilterOnly,
	}, nil
}

func (p *Proxy) Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no server command provided")
	}

	if err := p.preflight(ctx, args); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	bridge := NewBridge(os.Stdin, os.Stdout, serverIn, serverOut)
	filter := NewResponseFilter(p.enforcer, p.auditOnly)

	errCh := make(chan error, 2)

	// Server -> Host
	go func() {
		err := p.handleServerResponses(bridge, filter)
		cancel() // stop the other goroutine
		errCh <- err
	}()

	// Host -> Server
	go func() {
		err := p.handleHostRequests(bridge, filter)
		cancel() // stop the other goroutine
		errCh <- err
	}()

	err = <-errCh

	_ = serverIn.Close()
	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	if err == io.EOF {
		return nil
	}
	return err
}

func (p *Proxy) preflight(ctx context.Context, args []string) error {
	timeout := p.cfg.Timeout
	if timeout == 0 {
		timeout = scanner.DefaultTimeout
	}

	command := joinCommand(args)
	report, err := scanner.Scan(ctx, command, timeout)
	if err != nil {
		return fmt.Errorf("preflight scan failed: %w", err)
	}

	driftResult, err := differ.CompareV3(p.lockfile, report)
	if err != nil {
		return fmt.Errorf("preflight drift check failed: %w", err)
	}

	if driftResult.HasDrift {
		maxSeverity := p.getMaxDriftSeverity(driftResult)
		threshold := p.parseSeverityThreshold()

		if maxSeverity >= threshold {
			if p.auditOnly || p.filterOnly {
				mode := "audit-only"
				if p.filterOnly && !p.auditOnly {
					mode = "filter-only"
				}
				p.logAudit("preflight", "drift detected but continuing ("+mode+")", map[string]interface{}{
					"drift_count":  len(driftResult.Drifts),
					"max_severity": differ.SeverityString(maxSeverity),
				})
			} else {
				return fmt.Errorf("preflight failed: drift detected with severity %s (threshold: %s)",
					differ.SeverityString(maxSeverity), p.cfg.FailOn)
			}
		}
	}

	if p.cfg.PolicyPreset != "" {
		policyConfig := policy.GetPreset(p.cfg.PolicyPreset)
		if policyConfig == nil {
			return fmt.Errorf("policy preset %q not found", p.cfg.PolicyPreset)
		}

		policyInput := policy.BuildV3PolicyInput(p.lockfile, report, driftResult)
		engine, err := policy.NewEngine()
		if err != nil {
			return fmt.Errorf("failed to create policy engine: %w", err)
		}

		results, err := engine.EvaluateWithV3Input(policyConfig, &policyInput)
		if err != nil {
			return fmt.Errorf("policy evaluation failed: %w", err)
		}

		for _, r := range results {
			if !r.Passed && r.Severity == models.PolicySeverityError {
				if p.auditOnly || p.filterOnly {
					mode := "audit-only"
					if p.filterOnly && !p.auditOnly {
						mode = "filter-only"
					}
					p.logAudit("preflight", "policy violation but continuing ("+mode+")", map[string]interface{}{
						"rule": r.RuleName,
						"msg":  r.FailureMsg,
					})
				} else {
					return fmt.Errorf("preflight failed: policy rule %q violated: %s", r.RuleName, r.FailureMsg)
				}
			}
		}
	}

	if p.cfg.AllowStaticResources {
		staticURIs := extractResourceURIs(report.Resources)
		p.enforcer.SetStaticResources(staticURIs)
	}

	return nil
}

func (p *Proxy) handleHostRequests(bridge *Bridge, filter *ResponseFilter) error {
	for {
		req, err := bridge.ReadRequest()
		if err != nil {
			if errors.Is(err, ErrLineTooLong) {
				logOversizeNDJSON("host->proxy", "request")
			}
			return err
		}

		method, _ := req["method"].(string)
		id, hasId := req["id"]
		isNotification := !hasId

		switch method {
		case "tools/call":
			if p.filterOnly {
				break
			}
			if denied, reason, identifier := p.enforceToolsCall(req); denied {
				p.logBlock(method, identifier, reason, isNotification)
				if isNotification {
					continue
				}
				if err := bridge.WriteResponse(DenyError(id, reason)); err != nil {
					return err
				}
				continue
			}

		case "prompts/get":
			if p.filterOnly {
				break
			}
			if denied, reason, identifier := p.enforcePromptsGet(req); denied {
				p.logBlock(method, identifier, reason, isNotification)
				if isNotification {
					continue
				}
				if err := bridge.WriteResponse(DenyError(id, reason)); err != nil {
					return err
				}
				continue
			}

		case "resources/read":
			if p.filterOnly {
				break
			}
			if denied, reason, identifier := p.enforceResourcesRead(req); denied {
				p.logBlock(method, identifier, reason, isNotification)
				if isNotification {
					continue
				}
				if err := bridge.WriteResponse(DenyError(id, reason)); err != nil {
					return err
				}
				continue
			}
		}

		if !isNotification {
			proxyID, err := filter.Register(id, method)
			if err != nil {
				if err == ErrPendingMapFull {
					p.logBlock(method, "pending-map-full", "cannot register filter safely", false)
					if err := bridge.WriteResponse(OverloadedError(id)); err != nil {
						return err
					}
				} else {
					p.logBlock(method, "invalid-request-id", err.Error(), false)
					if err := bridge.WriteResponse(InvalidRequestError(id, err.Error())); err != nil {
						return err
					}
				}
				continue
			}
			req["id"] = proxyID
		}

		if err := bridge.ForwardToServer(req); err != nil {
			return err
		}
	}
}

func (p *Proxy) handleServerResponses(bridge *Bridge, filter *ResponseFilter) error {
	for {
		resp, err := bridge.ReadServerResponse()
		if err != nil {
			if errors.Is(err, ErrLineTooLong) {
				logOversizeNDJSON("server->proxy", "response")
			}
			return err
		}

		filtered, modified := filter.Apply(resp)
		if filtered == nil {
			// Unknown or duplicate response detected - log and drop
			p.logAudit("response", "dropped-unknown-or-duplicate", map[string]interface{}{
				"id": resp["id"],
			})
			continue
		}
		if modified {
			resp = filtered
		}

		if err := bridge.WriteResponse(resp); err != nil {
			return err
		}
	}
}

func (p *Proxy) enforceToolsCall(req map[string]interface{}) (denied bool, reason string, identifier string) {
	params, _ := req["params"].(map[string]interface{})
	name, _ := params["name"].(string)

	if !p.enforcer.AllowTool(name) {
		if p.auditOnly {
			p.logAudit("tools/call", "would-block", map[string]interface{}{"tool": name})
			return false, "", name
		}
		return true, fmt.Sprintf("tool %q not in lockfile allowlist", name), name
	}
	return false, "", name
}

func (p *Proxy) enforcePromptsGet(req map[string]interface{}) (denied bool, reason string, identifier string) {
	params, _ := req["params"].(map[string]interface{})
	name, _ := params["name"].(string)

	if !p.enforcer.AllowPrompt(name) {
		if p.auditOnly {
			p.logAudit("prompts/get", "would-block", map[string]interface{}{"prompt": name})
			return false, "", name
		}
		return true, fmt.Sprintf("prompt %q not in lockfile allowlist", name), name
	}
	return false, "", name
}

func (p *Proxy) enforceResourcesRead(req map[string]interface{}) (denied bool, reason string, identifier string) {
	params, _ := req["params"].(map[string]interface{})
	uri, _ := params["uri"].(string)

	if !p.enforcer.AllowResourceURI(uri) {
		if p.auditOnly {
			p.logAudit("resources/read", "would-block", map[string]interface{}{"uri": truncateURI(uri)})
			return false, "", truncateURI(uri)
		}
		return true, "resource URI does not match any locked template", truncateURI(uri)
	}
	return false, "", truncateURI(uri)
}

func (p *Proxy) logBlock(method, identifier, reason string, isNotification bool) {
	mode := "enforce"
	if p.auditOnly {
		mode = "audit-only"
	} else if p.filterOnly {
		mode = "filter-only"
	}

	entry := map[string]interface{}{
		"level":           "warn",
		"event":           "mcptrust.proxy.block",
		"method":          method,
		"identifier":      identifier,
		"reason":          reason,
		"mode":            mode,
		"is_notification": isNotification,
		"lockfile":        p.cfg.LockfilePath,
	}
	b, _ := json.Marshal(entry)
	fmt.Fprintln(os.Stderr, string(b))
}

func (p *Proxy) logAudit(method, action string, data map[string]interface{}) {
	entry := map[string]interface{}{
		"level":  "warn",
		"method": method,
		"action": action,
		"mode":   "audit-only",
	}
	for k, v := range data {
		entry[k] = v
	}
	b, _ := json.Marshal(entry)
	fmt.Fprintln(os.Stderr, string(b))
}

func logOversizeNDJSON(direction, phase string) {
	fmt.Fprintf(os.Stderr, "mcptrust: dropped_oversize_ndjson_line direction=%s limit_bytes=%d phase=%s\n",
		direction, MaxNDJSONLineSize, phase)
}

func (p *Proxy) getMaxDriftSeverity(result *differ.V3Result) differ.SeverityLevel {
	max := differ.SeveritySafe
	for _, d := range result.Drifts {
		if d.Severity > max {
			max = d.Severity
		}
	}
	return max
}

func (p *Proxy) parseSeverityThreshold() differ.SeverityLevel {
	switch p.cfg.FailOn {
	case "safe":
		return differ.SeveritySafe
	case "moderate":
		return differ.SeverityModerate
	default:
		return differ.SeverityCritical
	}
}

func joinCommand(args []string) string {
	result := ""
	for i, arg := range args {
		if i > 0 {
			result += " "
		}
		result += arg
	}
	return result
}

func extractResourceURIs(resources []models.Resource) []string {
	uris := make([]string, len(resources))
	for i, r := range resources {
		uris[i] = r.URI
	}
	return uris
}

func truncateURI(uri string) string {
	if len(uri) <= 50 {
		return uri
	}
	return uri[:47] + "..."
}
