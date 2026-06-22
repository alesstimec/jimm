// Copyright 2026 Canonical.

package jujuapi_test

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/canonical/jimm/v3/internal/jujuapi"
)

// TestModelConfigAdvertisesLegacyAndCurrent asserts the ModelConfig facade
// advertises both the 3.6 (v3) and 4.x (v4) versions.
func TestModelConfigAdvertisesLegacyAndCurrent(t *testing.T) {
	c := qt.New(t)
	c.Assert(jujuapi.SupportedFacades()["ModelConfig"], qt.DeepEquals, []int{3, 4})
}

// TestModelConfigModelGet checks ModelGet returns the simulated agent-version
// config; the same handler serves v3 and v4 (its wire format is unchanged).
func TestModelConfigModelGet(t *testing.T) {
	c := qt.New(t)

	cr := newTestControllerRoot(jujuJIMM(nil), "alice@external", true)

	res, err := cr.ModelGet(context.Background())
	c.Assert(err, qt.IsNil)
	_, ok := res.Config["agent-version"]
	c.Check(ok, qt.IsTrue)
}
