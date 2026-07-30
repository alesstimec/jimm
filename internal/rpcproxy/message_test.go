// Copyright 2026 Canonical.

package rpcproxy

import (
	"context"
	"errors"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/canonical/jimm/v3/internal/telemetry"
)

func TestFinishSpanNilReceiver(t *testing.T) {
	c := qt.New(t)

	var m *message
	// Should not panic.
	m.finishSpan(errors.New("boom"))
	m.finishSpan(nil)
	c.Check(true, qt.IsTrue) // reached without panic
}

func TestFinishSpanNoOpTracer(t *testing.T) {
	c := qt.New(t)

	_, span := telemetry.StartSpan(context.Background(), "test-span")
	m := &message{span: &span}

	// finishSpan with nil error — span is finished.
	m.finishSpan(nil)
	c.Check(m.span, qt.IsNil)

	// Double-finish is safe.
	m.finishSpan(nil)
	c.Check(m.span, qt.IsNil)
}

func TestFinishSpanWithError(t *testing.T) {
	c := qt.New(t)

	_, span := telemetry.StartSpan(context.Background(), "test-span")
	m := &message{span: &span}

	err := errors.New("something went wrong")
	m.finishSpan(err)
	c.Check(m.span, qt.IsNil)

	// Double-finish after error is safe.
	m.finishSpan(nil)
	c.Check(m.span, qt.IsNil)
}
