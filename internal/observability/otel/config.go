// Package otel provides OpenTelemetry tracing integration for mcptrust.
// Disabled by default; enabled via --otel flag.
package otel

import (
	"errors"
)

// Protocol constants for OTLP exporters.
const (
	ProtocolHTTP = "otlphttp"
	ProtocolGRPC = "otlpgrpc"
)

// Config holds OTel initialization options.
type Config struct {
	Enabled     bool
	Endpoint    string  // e.g., "http://localhost:4318" or "localhost:4317"
	Protocol    string  // "otlphttp" or "otlpgrpc"
	Insecure    bool    // allow insecure connections (no TLS)
	ServiceName string  // default: "mcptrust"
	SampleRatio float64 // 0..1, default: 1.0
}

// DefaultConfig returns a Config with safe defaults (OTel disabled).
func DefaultConfig() Config {
	return Config{
		Enabled:     false,
		Protocol:    ProtocolHTTP,
		ServiceName: "mcptrust",
		SampleRatio: 1.0,
	}
}

// Validate checks that the configuration is valid when OTel is enabled.
func (c Config) Validate() error {
	if !c.Enabled {
		return nil // nothing to validate if disabled
	}

	switch c.Protocol {
	case ProtocolHTTP, ProtocolGRPC:
		// valid
	default:
		return errors.New("otel: protocol must be 'otlphttp' or 'otlpgrpc'")
	}

	if c.SampleRatio < 0 || c.SampleRatio > 1 {
		return errors.New("otel: sample-ratio must be between 0 and 1")
	}

	return nil
}
