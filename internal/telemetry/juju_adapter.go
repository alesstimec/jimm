// Copyright 2026 Canonical.

package telemetry

import (
	"context"

	jujuTrace "github.com/juju/juju/core/trace"
	"github.com/juju/zaputil/zapctx"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const (
	// TraceIDLogField is the zap field key for the trace ID in log entries.
	// Uses the OpenTelemetry convention so Loki/Grafana can automatically
	// correlate logs to traces in Tempo.
	traceIDLogField = "trace_id"
)

// traceLoggerKey marks a context as already having the trace_id injected into
// its logger. A single context chain shares one trace ID, so we only need to
// add it once — at the first sampled span.
type traceLoggerKey struct{}

// traceIDAdded reports whether the trace_id field has already been injected
// into the context's logger.
func traceIDAdded(ctx context.Context) bool {
	return ctx.Value(traceLoggerKey{}) != nil
}

type otelTracer struct {
	tracer oteltrace.Tracer
}

// Start implements jujuTrace.Tracer.
func (t otelTracer) Start(ctx context.Context, name string, options ...jujuTrace.Option) (context.Context, jujuTrace.Span) {
	if t.tracer == nil {
		return ctx, jujuTrace.NoopSpan{}
	}

	ctx = remoteParentFromScope(ctx)

	spanOptions := []oteltrace.SpanStartOption{
		oteltrace.WithSpanKind(oteltrace.SpanKindServer),
	}
	attributes := toOTelAttributes(traceAttributes(options...))
	if len(attributes) != 0 {
		spanOptions = append(spanOptions, oteltrace.WithAttributes(attributes...))
	}

	ctx, span := t.tracer.Start(ctx, name, spanOptions...)
	wrapped := otelSpan{span: span}
	spanContext := span.SpanContext()
	if spanContext.IsValid() {
		ctx = jujuTrace.WithTraceScope(ctx, spanContext.TraceID().String(), spanContext.SpanID().String(), int(spanContext.TraceFlags()))

		// If the span is sampled, we add the trace ID to the logger context.
		// We don't add it again for child spans, because they all relate to
		// the same trace ID.
		if spanContext.TraceFlags().IsSampled() && !traceIDAdded(ctx) {
			ctx = zapctx.WithFields(ctx,
				zap.String(traceIDLogField, spanContext.TraceID().String()),
			)
			ctx = context.WithValue(ctx, traceLoggerKey{}, true)
		}
	}
	ctx = jujuTrace.WithSpan(ctx, wrapped)

	return ctx, wrapped
}

// Enabled implements jujuTrace.Tracer.
func (t otelTracer) Enabled() bool {
	return t.tracer != nil
}

func remoteParentFromScope(ctx context.Context) context.Context {
	if oteltrace.SpanContextFromContext(ctx).IsValid() {
		return ctx
	}

	traceID, spanID, flags, ok := jujuTrace.ScopeFromContext(ctx)
	if !ok {
		return ctx
	}

	otelTraceID, err := oteltrace.TraceIDFromHex(traceID)
	if err != nil {
		return ctx
	}
	otelSpanID, err := oteltrace.SpanIDFromHex(spanID)
	if err != nil {
		return ctx
	}
	if flags < 0 || flags > 255 {
		return ctx
	}

	spanContext := oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID:    otelTraceID,
		SpanID:     otelSpanID,
		TraceFlags: oteltrace.TraceFlags(flags),
		Remote:     true,
	})
	if !spanContext.IsValid() {
		return ctx
	}

	return oteltrace.ContextWithRemoteSpanContext(ctx, spanContext)
}

type otelSpan struct {
	span oteltrace.Span
}

// Scope returns a jujuTrace.Scope that reflects the trace context of
// the underlying OpenTelemetry span.
func (s otelSpan) Scope() jujuTrace.Scope {
	spanContext := s.span.SpanContext()
	if !spanContext.IsValid() {
		return jujuTrace.NoopScope{}
	}
	return otelScope{spanContext: spanContext}
}

// AddEvent adds an event to the span with the given name and attributes.
func (s otelSpan) AddEvent(name string, attributes ...jujuTrace.Attribute) {
	attrs := toOTelAttributes(attributes)
	if len(attrs) == 0 {
		s.span.AddEvent(name)
		return
	}
	s.span.AddEvent(name, oteltrace.WithAttributes(attrs...))
}

// RecordError records an error on the span with the given attributes.
func (s otelSpan) RecordError(err error, attributes ...jujuTrace.Attribute) {
	if err == nil {
		return
	}
	attrs := toOTelAttributes(attributes)
	if len(attrs) == 0 {
		s.span.RecordError(err)
	} else {
		s.span.RecordError(err, oteltrace.WithAttributes(attrs...))
	}
	s.span.SetStatus(codes.Error, err.Error())
}

// End ends the span with the given attributes.
func (s otelSpan) End(attributes ...jujuTrace.Attribute) {
	attrs := toOTelAttributes(attributes)
	if len(attrs) != 0 {
		s.span.SetAttributes(attrs...)
	}
	s.span.End()
}

type otelScope struct {
	spanContext oteltrace.SpanContext
}

// TraceID returns the trace ID of the span context.
func (s otelScope) TraceID() string {
	return s.spanContext.TraceID().String()
}

// SpanID returns the span ID of the span context.
func (s otelScope) SpanID() string {
	return s.spanContext.SpanID().String()
}

// TraceFlags returns the trace flags of the span context.
func (s otelScope) TraceFlags() int {
	return int(s.spanContext.TraceFlags())
}

// IsSampled returns true if the span context is sampled.
func (s otelScope) IsSampled() bool {
	return s.spanContext.TraceFlags().IsSampled()
}
