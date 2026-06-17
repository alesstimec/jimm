// Copyright 2026 Canonical.

package telemetry

import (
	"context"

	jujuTrace "github.com/juju/juju/core/trace"
	"go.opentelemetry.io/otel/attribute"
)

// TrackedSpan wraps a Juju span with a single error-aware finish path.
type TrackedSpan struct {
	span jujuTrace.Span
}

// StartSpan starts a named Juju trace span and returns a wrapper that records
// errors and final attributes consistently when finished.
func StartSpan(ctx context.Context, name string, attributes ...jujuTrace.Attribute) (context.Context, TrackedSpan) {
	options := []jujuTrace.Option(nil)
	if len(attributes) != 0 {
		options = append(options, jujuTrace.WithAttributes(attributes...))
	}
	ctx, span := jujuTrace.Start(ctx, jujuTrace.Name(name), options...)
	return ctx, TrackedSpan{span: span}
}

// Finish records err, if present, and ends the span with the provided attributes.
func (s TrackedSpan) Finish(err error, attributes ...jujuTrace.Attribute) {
	if s.span == nil {
		return
	}
	if err != nil {
		s.span.RecordError(err)
	}
	s.span.End(attributes...)
}

// Scope returns the trace scope for the wrapped span.
func (s TrackedSpan) Scope() jujuTrace.Scope {
	if s.span == nil {
		return jujuTrace.NoopScope{}
	}
	return s.span.Scope()
}

func traceAttributes(options ...jujuTrace.Option) []jujuTrace.Attribute {
	traceOptions := jujuTrace.NewTracerOptions()
	for _, option := range options {
		option(traceOptions)
	}
	return traceOptions.Attributes()
}

func toOTelAttributes(attributes []jujuTrace.Attribute) []attribute.KeyValue {
	result := make([]attribute.KeyValue, 0, len(attributes))
	for _, attr := range attributes {
		result = append(result, attribute.String(attr.Key(), attr.Value()))
	}
	return result
}
