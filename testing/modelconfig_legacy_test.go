// Copyright 2026 Canonical.

package testing

import (
	"testing"

	qt "github.com/frankban/quicktest"
	jujuparams "github.com/juju/juju/rpc/params"

	"github.com/canonical/jimm/v3/internal/testutils/jimmtest"
	jimmversion "github.com/canonical/jimm/v3/version"
)

// TestModelConfigV3ModelGet checks the ModelConfig facade version 3 (Juju 3.6)
// ModelGet handler returns the simulated controller agent-version config,
// via a hand-crafted version-pinned call. ModelGet returns a hardcoded config
// (JIMM does not dial a controller for it), so it works against a backing
// controller of any version. This mirrors TestModelGet, which covers v4.
func TestModelConfigV3ModelGet(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	conn := s.OpenNoClientVersion(c, nil, "alice@canonical.com", nil)
	defer conn.Close()

	var res jujuparams.ModelConfigResults
	err := conn.APICall(t.Context(), "ModelConfig", 3, "", "ModelGet", nil, &res)
	c.Assert(err, qt.IsNil)

	v, ok := res.Config["agent-version"]
	c.Assert(ok, qt.IsTrue)
	vers, ok := v.Value.(string)
	c.Assert(ok, qt.IsTrue)
	c.Check(vers, qt.Equals, jimmversion.ControllerVersion)
}
