// Copyright 2024 Canonical.

package rpc

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/juju/juju/core/flightrecorder"
	"github.com/juju/juju/core/trace"
	"github.com/juju/juju/rpc/rpcreflect"
	"github.com/juju/zaputil/zapctx"
	"go.uber.org/zap"

	"github.com/canonical/jimm/v3/internal/telemetry"
)

// A Root provides the root of an RPC server connection.
type Root struct {
	methodMu sync.RWMutex
	methods  map[string]rpcreflect.MethodCaller

	inflightMu sync.Mutex
	callID     uint64
	inflight   map[uint64]func()
}

// AddMethod adds, or replaces, the given method in the Root.
func (r *Root) AddMethod(rootName string, version int, methodName string, mc rpcreflect.MethodCaller) {
	r.methodMu.Lock()
	defer r.methodMu.Unlock()
	if r.methods == nil {
		r.methods = make(map[string]rpcreflect.MethodCaller)
	}
	r.methods[fmt.Sprintf("%s-%d-%s", rootName, version, methodName)] = mc
}

// RemoveMethod removes the given method from the Root.
func (r *Root) RemoveMethod(rootName string, version int, methodName string) {
	r.methodMu.Lock()
	defer r.methodMu.Unlock()
	delete(r.methods, fmt.Sprintf("%s-%d-%s", rootName, version, methodName))
}

// FindMethod implements rpc.Root.
func (r *Root) FindMethod(rootName string, version int, methodName string) (rpcreflect.MethodCaller, error) {
	key := fmt.Sprintf("%s-%d-%s", rootName, version, methodName)
	zapctx.Debug(context.Background(), "finding method", zap.String("root", rootName), zap.Int("version", version), zap.String("methodName", methodName))
	r.methodMu.RLock()
	defer r.methodMu.RUnlock()
	if caller, ok := r.methods[key]; ok {
		return rootMethodCaller{
			MethodCaller: caller,
			r:            r,
			methodName:   methodName,
			facadeName:   rootName,
			version:      version,
		}, nil
	}
	return nil, &rpcreflect.CallNotImplementedError{
		RootMethod: rootName,
		Version:    version,
		Method:     methodName,
	}
}

// FlightRecorder returns a no-op flight recorder.
func (r *Root) FlightRecorder() flightrecorder.FlightRecorder {
	return flightrecorder.NoopRecorder{}
}

// StartTrace returns the context unchanged with a no-op span.
func (r *Root) StartTrace(ctx context.Context) (context.Context, trace.Span) {
	return ctx, trace.NoopSpan{}
}

// Kill implements rpc.Root.
func (r *Root) Kill() {
	r.inflightMu.Lock()
	defer r.inflightMu.Unlock()
	// cancel all inflight requests.
	for _, cancel := range r.inflight {
		cancel()
	}
}

func (r *Root) start(ctx context.Context) (context.Context, uint64) {
	// #nosec G118 Cancel func is called when end is called
	ctx, cancel := context.WithCancel(ctx)
	r.inflightMu.Lock()
	defer r.inflightMu.Unlock()
	if r.inflight == nil {
		r.inflight = make(map[uint64]func())
	}
	callID := r.callID
	r.callID++
	r.inflight[callID] = cancel
	return ctx, callID
}

func (r *Root) end(callID uint64) {
	r.inflightMu.Lock()
	defer r.inflightMu.Unlock()
	cancel := r.inflight[callID]
	if cancel != nil {
		cancel()
	}
	delete(r.inflight, callID)
}

// rootMethodCaller wraps an rpcreflect.MethodCaller so that if the
// root's Kill method is called the context of the method will also be
// canceled.
type rootMethodCaller struct {
	rpcreflect.MethodCaller
	r *Root

	methodName string
	facadeName string
	version    int
}

// Call implements rpcreflect.MethodCaller.Call.
func (c rootMethodCaller) Call(ctx context.Context, objID string, arg reflect.Value) (reflect.Value, error) {
	ctx, callID := c.r.start(ctx)
	defer c.r.end(callID)
	ctx = zapctx.WithFields(ctx, zap.String("facade", c.facadeName))
	ctx = zapctx.WithFields(ctx, zap.String("method", c.methodName))
	ctx = zapctx.WithFields(ctx, zap.Int("version", c.version))
	ctx, span := telemetry.StartSpan(ctx, "jimm.facade")
	var err error
	defer func() {
		span.Finish(err,
			trace.StringAttr("facade.name", c.facadeName),
			trace.StringAttr("facade.method", c.methodName),
			trace.IntAttr("facade.version", c.version),
		)
	}()
	return c.MethodCaller.Call(ctx, objID, arg)
}
