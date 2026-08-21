// Copyright 2026 Canonical.

package rpcproxy

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"
)

// TestCheckClientModelCompatibility verifies the model-proxy compatibility
// rule: client major version must be >= the hosting controller's, an
// unversioned client is treated as Juju 3.6, an unknown controller version
// is rejected, and a context without compatibility inputs is not gated.
func TestCheckClientModelCompatibility(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		about             string
		clientVersion     string
		controllerVersion string
		expectError       string
	}{{
		about:             "unversioned client reaches a 3.6 model",
		clientVersion:     "",
		controllerVersion: "3.6.9",
	}, {
		about:             "unversioned client is refused a 4.x model",
		clientVersion:     "",
		controllerVersion: "4.0.2",
		expectError:       `your Juju client is not compatible with model "prod" \(4\.0\.2\); please upgrade your Juju client to interact with this model`,
	}, {
		about:             "3.6 client is refused a 4.x model",
		clientVersion:     "3.6.8",
		controllerVersion: "4.0.2",
		expectError:       `your Juju client is not compatible with model "prod" \(4\.0\.2\); please upgrade your Juju client to interact with this model`,
	}, {
		about:             "3.6 client reaches a 3.6 model",
		clientVersion:     "3.6.8",
		controllerVersion: "3.6.9",
	}, {
		about:             "4.x client reaches a 4.x model",
		clientVersion:     "4.0.2",
		controllerVersion: "4.0.5",
	}, {
		about:             "4.x client reaches a 3.6 model",
		clientVersion:     "4.0.2",
		controllerVersion: "3.6.9",
	}, {
		about:             "client with unparseable version is treated as 3.6",
		clientVersion:     "not-a-version",
		controllerVersion: "4.0.2",
		expectError:       `your Juju client is not compatible with model "prod" \(4\.0\.2\); please upgrade your Juju client to interact with this model`,
	}, {
		about:             "unknown controller version is rejected",
		clientVersion:     "4.0.2",
		controllerVersion: "",
		expectError:       `cannot establish that your Juju client is compatible with model "prod": the hosting controller's version is unknown`,
	}}

	for _, test := range tests {
		c.Run(test.about, func(c *qt.C) {
			ctx := ContextWithModelCompatibility(context.Background(), ModelCompatibility{
				ClientVersion:     test.clientVersion,
				ModelName:         "prod",
				ControllerVersion: test.controllerVersion,
			})
			err := checkClientModelCompatibility(ctx)
			if test.expectError == "" {
				c.Check(err, qt.IsNil)
			} else {
				c.Check(err, qt.ErrorMatches, test.expectError)
			}
		})
	}

	c.Run("context without compatibility inputs is not gated", func(c *qt.C) {
		c.Check(checkClientModelCompatibility(context.Background()), qt.IsNil)
	})
}
