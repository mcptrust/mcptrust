package otel

import (
	"context"
	"os"

	"github.com/mcptrust/mcptrust/internal/version"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Init constructs tracer provider
func Init(ctx context.Context, cfg Config) (*Handle, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Resolve endpoint with defaults
	endpoint := cfg.Endpoint
	if endpoint == "" {
		// Check env var first
		if envEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); envEndpoint != "" {
			endpoint = envEndpoint
		} else {
			// Use protocol-appropriate defaults
			switch cfg.Protocol {
			case ProtocolGRPC:
				endpoint = "localhost:4317"
			default:
				endpoint = "http://localhost:4318"
			}
		}
	}

	// Build resource with service info
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(version.BuildVersion()),
			semconv.TelemetrySDKLanguageGo,
			semconv.TelemetrySDKVersion(otel.Version()),
		),
	)
	if err != nil {
		return nil, err
	}

	// Create exporter based on protocol
	var exporter sdktrace.SpanExporter
	switch cfg.Protocol {
	case ProtocolGRPC:
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(endpoint),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		exporter, err = otlptracegrpc.New(ctx, opts...)
	default: // otlphttp
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(endpoint),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		exporter, err = otlptracehttp.New(ctx, opts...)
	}
	if err != nil {
		return nil, err
	}

	// Create sampler
	var sampler sdktrace.Sampler
	if cfg.SampleRatio >= 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else if cfg.SampleRatio <= 0 {
		sampler = sdktrace.NeverSample()
	} else {
		sampler = sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRatio))
	}

	// Create TracerProvider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	// Set as global provider
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	// Create tracer
	tracer := tp.Tracer("mcptrust")

	return &Handle{
		Tracer: tracer,
		Shutdown: func(ctx context.Context) error {
			return tp.Shutdown(ctx)
		},
	}, nil
}

// InitWithProvider for testing
func InitWithProvider(tp trace.TracerProvider) *Handle {
	return &Handle{
		Tracer:   tp.Tracer("mcptrust"),
		Shutdown: func(ctx context.Context) error { return nil },
	}
}
