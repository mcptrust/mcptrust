package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/mcptrust/mcptrust/internal/observability"
	"github.com/mcptrust/mcptrust/internal/observability/logging"
	otelobs "github.com/mcptrust/mcptrust/internal/observability/otel"
	"github.com/mcptrust/mcptrust/internal/observability/receipt"
	"github.com/mcptrust/mcptrust/internal/version"
	"github.com/spf13/cobra"
)

var (
	logFormatFlag   string
	logLevelFlag    string
	logOutputFlag   string
	receiptPathFlag string
	receiptModeFlag string

	// OTel flags
	otelEnabledFlag     bool
	otelEndpointFlag    string
	otelProtocolFlag    string
	otelInsecureFlag    bool
	otelServiceNameFlag string
	otelSampleRatioFlag float64
)

var rootCmd = &cobra.Command{
	Use:   "mcptrust",
	Short: "Security scanner for MCP servers",
	Long: `mcptrust: lockfile for the Agentic Web.
Secures AI agents by verifying MCP servers before use.`,
	Version: version.BuildVersion(),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Initialize context with operation ID
		ctx := observability.WithOpID(context.Background())

		// Create logger from flags
		logger, err := logging.NewLogger(logging.Config{
			Format: logFormatFlag,
			Level:  logLevelFlag,
			Output: logOutputFlag,
		})
		if err != nil {
			return fmt.Errorf("failed to initialize logger: %w", err)
		}

		// Store logger in context
		ctx = logging.WithLogger(ctx, logger)

		// Initialize receipt writer if --receipt is set
		if receiptPathFlag != "" {
			mode := receiptModeFlag
			if mode == "" {
				mode = "overwrite"
			}
			rw, err := receipt.NewWriter(receiptPathFlag, mode)
			if err != nil {
				return fmt.Errorf("failed to initialize receipt writer: %w", err)
			}
			ctx = receipt.WithWriter(ctx, rw)
		}

		// Initialize OTel if enabled
		if otelEnabledFlag {
			cfg := otelobs.Config{
				Enabled:     true,
				Endpoint:    otelEndpointFlag,
				Protocol:    otelProtocolFlag,
				Insecure:    otelInsecureFlag,
				ServiceName: otelServiceNameFlag,
				SampleRatio: otelSampleRatioFlag,
			}
			h, err := otelobs.Init(ctx, cfg)
			if err != nil {
				// Log warning but don't fail - OTel is optional
				logger.Warn("otel", "failed to initialize OTel tracing", "error", err.Error())
			} else {
				ctx = otelobs.WithHandle(ctx, h)
			}
		}

		cmd.SetContext(ctx)

		return nil
	},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if ctx == nil {
			return nil
		}

		var errs []error

		// Shutdown OTel with timeout (warn-only, never fatal)
		// OTel failures should not affect command exit code
		if h := otelobs.From(ctx); h != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			if err := h.Shutdown(shutdownCtx); err != nil {
				// Log warning but don't add to errs - graceful degradation
				if lg := logging.From(ctx); lg != nil {
					lg.Warn("otel", "shutdown failed", "error", err.Error())
				}
			}
			cancel()
		}

		// Close receipt writer (fatal - evidence not written)
		if rw := receipt.From(ctx); rw != nil {
			errs = append(errs, rw.Close())
		}

		// Close logger (fatal - flush buffers)
		if lg := logging.From(ctx); lg != nil {
			errs = append(errs, lg.Close())
		}

		return errors.Join(errs...)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// Logging flags
	rootCmd.PersistentFlags().StringVar(&logFormatFlag, "log-format", "pretty",
		"Log format: pretty (default, no structured logs) or jsonl (SIEM-friendly)")
	rootCmd.PersistentFlags().StringVar(&logLevelFlag, "log-level", "info",
		"Log level: debug, info, warn, error")
	rootCmd.PersistentFlags().StringVar(&logOutputFlag, "log-output", "stderr",
		"Log output: stderr (default) or file path")

	// Receipt flags
	rootCmd.PersistentFlags().StringVar(&receiptPathFlag, "receipt", "",
		"Path to write receipt artifact (disabled if empty)")
	rootCmd.PersistentFlags().StringVar(&receiptModeFlag, "receipt-mode", "overwrite",
		"Receipt mode: overwrite (default) or append")

	// OTel flags
	rootCmd.PersistentFlags().BoolVar(&otelEnabledFlag, "otel", false,
		"Enable OpenTelemetry tracing (disabled by default)")
	rootCmd.PersistentFlags().StringVar(&otelEndpointFlag, "otel-endpoint", "",
		"OTel exporter endpoint (default: OTEL_EXPORTER_OTLP_ENDPOINT or http://localhost:4318)")
	rootCmd.PersistentFlags().StringVar(&otelProtocolFlag, "otel-protocol", "otlphttp",
		"OTel protocol: otlphttp (default) or otlpgrpc")
	rootCmd.PersistentFlags().BoolVar(&otelInsecureFlag, "otel-insecure", false,
		"Allow insecure OTel connections (no TLS)")
	rootCmd.PersistentFlags().StringVar(&otelServiceNameFlag, "otel-service-name", "mcptrust",
		"OTel service name for traces")
	rootCmd.PersistentFlags().Float64Var(&otelSampleRatioFlag, "otel-sample-ratio", 1.0,
		"OTel sampling ratio (0.0-1.0)")

	rootCmd.AddCommand(GetScanCmd())
	rootCmd.AddCommand(GetLockCmd())
	rootCmd.AddCommand(GetCheckCmd())
	rootCmd.AddCommand(GetDiffCmd())
	rootCmd.AddCommand(GetPolicyCmd())
	rootCmd.AddCommand(GetKeygenCmd())
	rootCmd.AddCommand(GetSignCmd())
	rootCmd.AddCommand(GetVerifyCmd())
	rootCmd.AddCommand(GetBundleCmd())
	rootCmd.AddCommand(GetArtifactCmd())
	rootCmd.AddCommand(GetRunCmd())
	rootCmd.AddCommand(GetProxyCmd())
}
