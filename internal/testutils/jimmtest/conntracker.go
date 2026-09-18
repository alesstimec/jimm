// Copyright 2026 Canonical.

package jimmtest

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/juju/names/v6"

	"github.com/canonical/jimm/v3/internal/dbmodel"
	"github.com/canonical/jimm/v3/internal/rpc"
)

// A ConnTracker records the controller websocket connections opened
// through its Dial function and forgets them when they are closed, so a
// test environment can assert that JIMM leaked none at teardown. Each
// environment owns its own tracker, so trackers do not interfere across
// tests and parallel tests are safe.
type ConnTracker struct {
	mu    sync.Mutex
	conns map[*trackedConn]connInfo
}

type connInfo struct {
	controller string
	modelTag   string
	dialStack  []byte
}

// A trackedConn removes itself from its tracker when closed.
type trackedConn struct {
	rpc.Conn
	untrack func()
	once    sync.Once
}

// Close implements rpc.Conn.
func (c *trackedConn) Close() error {
	c.once.Do(c.untrack)
	return c.Conn.Close()
}

// NewConnTracker returns a new, empty ConnTracker.
func NewConnTracker() *ConnTracker {
	return &ConnTracker{conns: make(map[*trackedConn]connInfo)}
}

// Dial is an rpc.DialFn that dials via rpc.Dial and records the
// resulting connection until it is closed.
func (t *ConnTracker) Dial(ctx context.Context, ctl *dbmodel.Controller, modelTag names.ModelTag, finalPath string, headers http.Header, attrs url.Values) (rpc.Conn, error) {
	conn, err := rpc.Dial(ctx, ctl, modelTag, finalPath, headers, attrs)
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{Conn: conn}
	tc.untrack = func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		delete(t.conns, tc)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.conns[tc] = connInfo{
		controller: ctl.Name,
		modelTag:   modelTag.Id(),
		dialStack:  debug.Stack(),
	}
	return tc, nil
}

// CheckNoLeaks fails the test if any tracked connection is still open,
// reporting where each leaked connection was dialed from and closing it
// so it cannot disturb later tests. Deregistration is asynchronous
// (rpc.Client.Close completes in the receive goroutine when the close
// handshake finishes), so correctly-closed connections are given
// drainTimeout to disappear.
func (t *ConnTracker) CheckNoLeaks(c *qt.C, drainTimeout time.Duration) {
	deadline := time.Now().Add(drainTimeout)
	for {
		t.mu.Lock()
		if len(t.conns) == 0 {
			t.mu.Unlock()
			return
		}
		if time.Now().After(deadline) {
			break
		}
		t.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	// Still locked; report and close what is left.
	var sb strings.Builder
	leaked := make([]*trackedConn, 0, len(t.conns))
	for tc, info := range t.conns {
		leaked = append(leaked, tc)
		fmt.Fprintf(&sb, "leaked connection to controller %q (model %q), dialed from:\n%s\n",
			info.controller, info.modelTag, info.dialStack)
	}
	n := len(leaked)
	t.mu.Unlock()
	for _, tc := range leaked {
		_ = tc.Close()
	}
	c.Errorf("JIMM leaked %d controller connection(s):\n%s", n, sb.String())
}
