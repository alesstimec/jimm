// Copyright 2025 Canonical.

package jujuapi

import (
	"context"

	"github.com/juju/juju/rpc/params"

	"github.com/canonical/jimm/v3/internal/jujuapi/rpc"
	jimmversion "github.com/canonical/jimm/v3/version"
)

func init() {
	facadeInit["ModelConfig"] = func(r *controllerRoot) []int {
		modelGetMethod := rpc.Method(r.ModelGet)

		// ModelGet returns a generic config map (no model owner), so its wire
		// format is identical at v3 (Juju 3.6) and v4 (Juju 4.x); the same
		// handler is registered at both versions.
		r.AddMethod("ModelConfig", 3, "ModelGet", modelGetMethod)
		r.AddMethod("ModelConfig", 4, "ModelGet", modelGetMethod)
		return []int{3, 4}
	}
}

// ModelGet returns the model configuration in JIMM's case, this is used to return the "controller" model config.
// As JIMM doesn't have a controller model, or even an agent for that matter, we simulate this.
//
// It is required because the CLI reports on the agent-version during a show-controller call.
func (r *controllerRoot) ModelGet(ctx context.Context) (params.ModelConfigResults, error) {
	return params.ModelConfigResults{
		Config: map[string]params.ConfigValue{
			"agent-version": {
				Value:  jimmversion.ControllerVersion,
				Source: "jimm",
			},
		},
	}, nil
}
