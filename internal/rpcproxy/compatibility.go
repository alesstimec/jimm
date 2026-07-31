// Copyright 2026 Canonical.

package rpcproxy

import (
	"context"

	"github.com/juju/version/v2"
	"github.com/juju/zaputil/zapctx"
	"go.uber.org/zap"

	"github.com/canonical/jimm/v3/internal/errors"
)

// ModelCompatibility carries the inputs for the client/model compatibility
// rule enforced on proxied model connections. The HTTP layer stores it in
// the request context with [ContextWithModelCompatibility]; the proxy
// applies the rule at user login. A context without this value is not gated.
type ModelCompatibility struct {
	// ClientVersion is the raw X-Juju-ClientVersion websocket upgrade
	// header, empty when the client sent none.
	ClientVersion string
	// ModelName is used in client-facing error messages.
	ModelName string
	// ControllerVersion is the agent version of the model's hosting
	// controller, which serves the model's API and therefore determines
	// compatibility (not the model's own agent version).
	ControllerVersion string
}

type modelCompatibilityContextKey struct{}

// ContextWithModelCompatibility returns a context carrying the inputs for
// the client/model compatibility check applied at user login on proxied
// model connections.
func ContextWithModelCompatibility(ctx context.Context, mc ModelCompatibility) context.Context {
	return context.WithValue(ctx, modelCompatibilityContextKey{}, mc)
}

// checkClientModelCompatibility rejects a user's model connection when the
// model's hosting controller has a higher major version than the client
// reports; a client reporting no (or an unparseable) version is treated as
// Juju 3.6 (fail closed), and a controller with an unknown agent version is
// likewise rejected. The rule applies to user logins only — agent and
// anonymous logins are redirected to, or handled by, the backing controller
// and never reach this check.
func checkClientModelCompatibility(ctx context.Context) error {
	mc, ok := ctx.Value(modelCompatibilityContextKey{}).(ModelCompatibility)
	if !ok {
		return nil
	}
	controllerVersion, err := version.Parse(mc.ControllerVersion)
	if err != nil {
		zapctx.Warn(ctx, "rejecting model connection: unknown controller agent version",
			zap.String("controller-version", mc.ControllerVersion))
		return errors.Codef(errors.CodeNotSupported,
			"cannot establish that your Juju client is compatible with model %q: the hosting controller's version is unknown", mc.ModelName)
	}
	// Juju 3.6 clients do not report their version, so an absent (or
	// unparseable) version means 3.6 — same resolution as model placement
	// in internal/jujuapi.
	clientMajor := 3
	if v, err := version.Parse(mc.ClientVersion); err == nil {
		clientMajor = v.Major
	}
	if controllerVersion.Major > clientMajor {
		zapctx.Info(ctx, "rejecting model connection from incompatible client",
			zap.String("client-version", mc.ClientVersion),
			zap.String("controller-version", mc.ControllerVersion))
		return errors.Codef(errors.CodeNotSupported,
			"your Juju client is not compatible with model %q (%s); please upgrade your Juju client to interact with this model",
			mc.ModelName, mc.ControllerVersion)
	}
	return nil
}
