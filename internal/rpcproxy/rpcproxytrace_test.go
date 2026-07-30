// Copyright 2026 Canonical.

package rpcproxy

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"
	jujuTrace "github.com/juju/juju/core/trace"
	"go.uber.org/mock/gomock"

	"github.com/canonical/jimm/v3/internal/telemetry/mocks"
)

func TestAddMessageStartsModelProxySpanAndPropagatesTrace(t *testing.T) {
	c := qt.New(t)
	ctrl := gomock.NewController(t)

	tracer := mocks.NewMockTracer(ctrl)
	span := mocks.NewMockSpan(ctrl)
	scope := mocks.NewMockScope(ctrl)

	const (
		incomingTraceID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		incomingSpanID  = "bbbbbbbbbbbbbbbb"
		childTraceID    = incomingTraceID
		childSpanID     = "cccccccccccccccc"
	)

	tracer.EXPECT().Enabled().Return(true).AnyTimes()
	tracer.EXPECT().Start(gomock.Any(), "jimm.model-proxy", gomock.Any()).DoAndReturn(
		func(ctx context.Context, _ string, _ ...jujuTrace.Option) (context.Context, jujuTrace.Span) {
			traceID, spanID, flags, ok := jujuTrace.ScopeFromContext(ctx)
			c.Check(ok, qt.IsTrue)
			c.Check(traceID, qt.Equals, incomingTraceID)
			c.Check(spanID, qt.Equals, incomingSpanID)
			c.Check(flags, qt.Equals, 1)
			return jujuTrace.WithSpan(ctx, span), span
		},
	)
	span.EXPECT().Scope().Return(scope)
	scope.EXPECT().TraceID().Return(childTraceID)
	scope.EXPECT().SpanID().Return(childSpanID)
	scope.EXPECT().TraceFlags().Return(1)

	msgs := inflightMsgs{messages: make(map[uint64]*message)}
	msg := &message{
		RequestID:  1,
		Type:       "Client",
		Version:    7,
		Request:    "FullStatus",
		TraceID:    incomingTraceID,
		SpanID:     incomingSpanID,
		TraceFlags: 1,
	}

	msgs.addMessage(jujuTrace.WithTracer(context.Background(), tracer), msg)

	c.Check(msg.start.IsZero(), qt.IsFalse)
	c.Check(msg.span, qt.Not(qt.IsNil))
	c.Check(msg.TraceID, qt.Equals, childTraceID)
	c.Check(msg.SpanID, qt.Equals, childSpanID)
	c.Check(msg.TraceFlags, qt.Equals, 1)
	c.Check(msgs.getMessage(msg.RequestID), qt.Equals, msg)
}

func TestRemoveMessageFinishesSpan(t *testing.T) {
	c := qt.New(t)
	ctrl := gomock.NewController(t)

	tracer := mocks.NewMockTracer(ctrl)
	span := mocks.NewMockSpan(ctrl)
	scope := mocks.NewMockScope(ctrl)

	tracer.EXPECT().Enabled().Return(true).AnyTimes()
	tracer.EXPECT().Start(gomock.Any(), "jimm.model-proxy", gomock.Any()).DoAndReturn(
		func(ctx context.Context, _ string, _ ...jujuTrace.Option) (context.Context, jujuTrace.Span) {
			return jujuTrace.WithSpan(ctx, span), span
		},
	)
	span.EXPECT().Scope().Return(scope)
	scope.EXPECT().TraceID().Return("")
	scope.EXPECT().SpanID().Return("")
	scope.EXPECT().TraceFlags().Return(0)
	span.EXPECT().End()

	msgs := inflightMsgs{messages: make(map[uint64]*message)}
	msg := &message{RequestID: 1, Type: "Client", Version: 7, Request: "FullStatus"}

	msgs.addMessage(jujuTrace.WithTracer(context.Background(), tracer), msg)
	msgs.removeMessage(msg.RequestID)

	c.Check(msg.span, qt.IsNil)
	c.Check(msgs.getMessage(msg.RequestID), qt.IsNil)
}

func TestFinishSpanRecordsError(t *testing.T) {
	c := qt.New(t)
	ctrl := gomock.NewController(t)

	tracer := mocks.NewMockTracer(ctrl)
	span := mocks.NewMockSpan(ctrl)
	scope := mocks.NewMockScope(ctrl)
	err := errTestSpan

	tracer.EXPECT().Enabled().Return(true).AnyTimes()
	tracer.EXPECT().Start(gomock.Any(), "jimm.model-proxy", gomock.Any()).DoAndReturn(
		func(ctx context.Context, _ string, _ ...jujuTrace.Option) (context.Context, jujuTrace.Span) {
			return jujuTrace.WithSpan(ctx, span), span
		},
	)
	span.EXPECT().Scope().Return(scope)
	scope.EXPECT().TraceID().Return("")
	scope.EXPECT().SpanID().Return("")
	scope.EXPECT().TraceFlags().Return(0)
	span.EXPECT().RecordError(err)
	span.EXPECT().End()

	msgs := inflightMsgs{messages: make(map[uint64]*message)}
	msg := &message{RequestID: 1, Type: "Client", Version: 7, Request: "FullStatus"}

	msgs.addMessage(jujuTrace.WithTracer(context.Background(), tracer), msg)
	msg.finishSpan(err)

	c.Check(msg.span, qt.IsNil)
}

var errTestSpan = &testSpanError{}

type testSpanError struct{}

func (*testSpanError) Error() string { return "span failed" }
