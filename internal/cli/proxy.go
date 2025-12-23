package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/mcptrust/mcptrust/internal/locker"
	"github.com/mcptrust/mcptrust/internal/observability/logging"
	"github.com/mcptrust/mcptrust/internal/proxy"
	"github.com/spf13/cobra"
)

var (
	proxyLockFlag             string
	proxyTimeoutFlag          time.Duration
	proxyFailOnFlag           string
	proxyPolicyFlag           string
	proxyAuditOnlyFlag        bool
	proxyFilterOnlyFlag       bool
	proxyPrintAllowlistFlag   bool
	proxyAllowStaticResources bool
)

var proxyCmd = &cobra.Command{
	Use:   "proxy [flags] -- <server-command> [server-args...]",
	Short: "Run as stdio enforcement proxy",
	Long: `Start an enforcement proxy between host and MCP server.

The proxy enforces v3 lockfile allowlists at runtime:
- Filters tools/list, prompts/list, resources/templates/list to only show allowed items
- Blocks tools/call, prompts/get, resources/read for non-allowlisted items
- Runs preflight drift detection before bridging traffic

Example:
  mcptrust proxy --lock mcp-lock.json -- npx -y @modelcontextprotocol/server-filesystem /tmp

Rollout mode (log but don't block):
  mcptrust proxy --audit-only --lock mcp-lock.json -- npx -y ...`,
	RunE:               runProxy,
	DisableFlagParsing: false,
}

func init() {
	proxyCmd.Flags().StringVar(&proxyLockFlag, "lock", "", "Path to v3 lockfile (required)")
	proxyCmd.Flags().DurationVar(&proxyTimeoutFlag, "timeout", 10*time.Second, "Server startup timeout")
	proxyCmd.Flags().StringVar(&proxyFailOnFlag, "fail-on", "critical", "Drift severity threshold: critical|moderate|info")
	proxyCmd.Flags().StringVar(&proxyPolicyFlag, "policy", "", "Policy preset name (optional)")
	proxyCmd.Flags().BoolVar(&proxyAuditOnlyFlag, "audit-only", false, "Log blocked requests but allow traffic (no filtering)")
	proxyCmd.Flags().BoolVar(&proxyFilterOnlyFlag, "filter-only", false, "Filter lists but don't block calls/reads")
	proxyCmd.Flags().BoolVar(&proxyPrintAllowlistFlag, "print-effective-allowlist", false, "Print derived allowlist and exit")
	proxyCmd.Flags().BoolVar(&proxyAllowStaticResources, "allow-static-resources", false, "Allow resources from startup resources/list")

	_ = proxyCmd.MarkFlagRequired("lock")
}

// GetProxyCmd returns the proxy command
func GetProxyCmd() *cobra.Command {
	return proxyCmd
}

func runProxy(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	log := logging.From(ctx)

	// Handle --print-effective-allowlist first (no server command needed)
	if proxyPrintAllowlistFlag {
		return printEffectiveAllowlist()
	}

	// Get server command from args after --
	serverArgs := args
	if len(serverArgs) == 0 {
		return fmt.Errorf("no server command provided; use: mcptrust proxy --lock FILE -- <server-command>")
	}

	if log != nil {
		log.Event(ctx, "proxy.start", map[string]any{
			"lockfile":    proxyLockFlag,
			"audit_only":  proxyAuditOnlyFlag,
			"filter_only": proxyFilterOnlyFlag,
			"fail_on":     proxyFailOnFlag,
		})
	}

	cfg := proxy.Config{
		LockfilePath:         proxyLockFlag,
		Timeout:              proxyTimeoutFlag,
		FailOn:               proxyFailOnFlag,
		PolicyPreset:         proxyPolicyFlag,
		AuditOnly:            proxyAuditOnlyFlag,
		FilterOnly:           proxyFilterOnlyFlag,
		AllowStaticResources: proxyAllowStaticResources,
	}

	p, err := proxy.New(cfg)
	if err != nil {
		if log != nil {
			log.Event(ctx, "proxy.complete", map[string]any{
				"status": "error",
				"error":  err.Error(),
			})
		}
		return fmt.Errorf("failed to create proxy: %w", err)
	}

	err = p.Run(ctx, serverArgs)
	if err != nil {
		if log != nil {
			log.Event(ctx, "proxy.complete", map[string]any{
				"status": "error",
				"error":  err.Error(),
			})
		}
		return err
	}

	if log != nil {
		log.Event(ctx, "proxy.complete", map[string]any{
			"status": "success",
		})
	}

	return nil
}

// printEffectiveAllowlist prints the derived allowlist for debugging
func printEffectiveAllowlist() error {
	mgr := locker.NewManager()
	lockfile, err := mgr.LoadV3(proxyLockFlag)
	if err != nil {
		return fmt.Errorf("failed to load lockfile: %w", err)
	}

	output := map[string]interface{}{
		"lockfile": proxyLockFlag,
		"tools":    sortedKeys(lockfile.Tools),
		"prompts":  sortedKeys(lockfile.Prompts.Definitions),
		"templates": func() []string {
			var uris []string
			for _, t := range lockfile.Resources.Templates {
				uris = append(uris, t.URITemplate)
			}
			return uris
		}(),
	}

	// Also compile and show template regex patterns
	var patterns []string
	for _, t := range lockfile.Resources.Templates {
		re, err := proxy.CompileTemplateMatcher(t.URITemplate)
		if err != nil {
			patterns = append(patterns, fmt.Sprintf("%s (ERROR: %v)", t.URITemplate, err))
		} else {
			patterns = append(patterns, re.String())
		}
	}
	output["template_patterns"] = patterns

	b, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(b))
	return nil
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
