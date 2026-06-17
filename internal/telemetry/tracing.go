// Copyright 2026 Canonical.

package telemetry

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	jujuTrace "github.com/juju/juju/core/trace"
	"github.com/juju/zaputil/zapctx"
	otlpgrpc "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	otlphttp "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.uber.org/zap"
)

const (
	defaultTraceProtocol = "http/protobuf"
	tracerName           = "github.com/canonical/jimm/v3"
)

// Params holds the OpenTelemetry exporter configuration used to send spans.
type Params struct {
	ServiceName string
	Endpoint    string
	Protocol    string
	SampleRatio *float64
}

// Verify validates the tracing configuration and normalizes default values.
//
// An empty endpoint disables OTLP export, so the remaining fields are only
// validated when tracing is enabled.
func (p *Params) Verify() error {
	if p == nil {
		return nil
	}

	p.Endpoint = strings.TrimSpace(p.Endpoint)
	if p.Endpoint == "" {
		return nil
	}

	if _, err := parseEndpoint(p.Endpoint); err != nil {
		return fmt.Errorf("invalid OTLP trace endpoint %q: %w", p.Endpoint, err)
	}

	p.Protocol = strings.ToLower(strings.TrimSpace(p.Protocol))
	if p.Protocol == "" {
		p.Protocol = defaultTraceProtocol
	}
	switch p.Protocol {
	case "grpc", "http/protobuf":
	default:
		return fmt.Errorf("unsupported OTLP trace protocol %q", p.Protocol)
	}

	if p.SampleRatio != nil && (*p.SampleRatio < 0 || *p.SampleRatio > 1) {
		return fmt.Errorf("OTLP trace sample ratio must be between 0 and 1, got %v", *p.SampleRatio)
	}

	return nil
}

// NewTracer returns a Juju-compatible tracer backed by OpenTelemetry when OTLP
// export is configured.
func NewTracer(ctx context.Context, params Params) (jujuTrace.Tracer, func(context.Context) error, error) {
	if err := params.Verify(); err != nil {
		return nil, nil, err
	}
	if !tracingConfigured(params) {
		return jujuTrace.NoopTracer{}, func(context.Context) error { return nil }, nil
	}

	exporter, err := newExporter(ctx, params)
	if err != nil {
		return nil, nil, err
	}

	providerOptions := []sdktrace.TracerProviderOption{sdktrace.WithBatcher(exporter)}
	if params.SampleRatio != nil {
		providerOptions = append(providerOptions, sdktrace.WithSampler(
			sdktrace.ParentBased(sdktrace.TraceIDRatioBased(*params.SampleRatio)),
		))
	}
	if serviceName := strings.TrimSpace(params.ServiceName); serviceName != "" {
		providerOptions = append(providerOptions, sdktrace.WithResource(
			resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceName(serviceName)),
		))
	}
	provider := sdktrace.NewTracerProvider(providerOptions...)
	zapctx.Info(ctx, "otlp tracing enabled", zap.String("protocol", params.Protocol))

	return otelTracer{tracer: provider.Tracer(tracerName)}, provider.Shutdown, nil
}

func tracingConfigured(params Params) bool {
	return strings.TrimSpace(params.Endpoint) != ""
}

func newExporter(ctx context.Context, params Params) (sdktrace.SpanExporter, error) {
	switch params.Protocol {
	case "grpc":
		option, err := grpcEndpointOption(params.Endpoint)
		if err != nil {
			return nil, err
		}
		return otlpgrpc.New(ctx, option)
	case "http/protobuf":
		option, err := httpEndpointOption(params.Endpoint)
		if err != nil {
			return nil, err
		}
		return otlphttp.New(ctx, option)
	default:
		return nil, fmt.Errorf("unsupported OTLP trace protocol %q", params.Protocol)
	}
}

func grpcEndpointOption(endpoint string) (otlpgrpc.Option, error) {
	parsed, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "" {
		return otlpgrpc.WithEndpointURL(parsed.String()), nil
	}
	return otlpgrpc.WithEndpoint(parsed.Host), nil
}

func httpEndpointOption(endpoint string) (otlphttp.Option, error) {
	parsed, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "" {
		return otlphttp.WithEndpointURL(parsed.String()), nil
	}
	return otlphttp.WithEndpoint(parsed.Host), nil
}

func parseEndpoint(endpoint string) (*url.URL, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if parsed.Host != "" {
		return parsed, nil
	}

	parsed, err = url.Parse("//" + endpoint)
	if err != nil {
		return nil, err
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("missing host")
	}
	if parsed.Path != "" {
		return nil, fmt.Errorf("unexpected path %q without scheme", parsed.Path)
	}
	return parsed, nil
}
