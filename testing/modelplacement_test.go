// Copyright 2026 Canonical.

package testing

import (
	"database/sql"
	"testing"

	petname "github.com/dustinkirkland/golang-petname"
	qt "github.com/frankban/quicktest"
	"github.com/juju/juju/api"
	jujuparams "github.com/juju/juju/rpc/params"
	"github.com/juju/names/v6"
	"github.com/juju/version/v2"

	"github.com/canonical/jimm/v3/internal/dbmodel"
	"github.com/canonical/jimm/v3/internal/testutils/jimmtest"
)

// TestModelPlacementByClientVersion exercises client-version-driven model
// placement end to end: a real websocket dial to JIMM carrying a chosen
// X-Juju-ClientVersion header, JIMM's header extraction, and placement
// against the real backing fleet. Per the JIMM/Juju interoperability spec, a
// new model may only be placed on a controller whose major version is <= the
// client's reported major version, and a client that reports no version is
// treated as a Juju 3.6 client (fail closed).
//
// Expectations branch on the composition of the backing fleet, so the test is
// meaningful whether the environment provides 3.x controllers, 4.x
// controllers, or a mix.
func TestModelPlacementByClientVersion(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	has3x := s.HasControllerWithMajorVersionAtMost(c, 3)

	// createModel creates a model over the given connection using the
	// current (v11) wire format and returns the response and error.
	createModel := func(c *qt.C, conn api.Connection) (jujuparams.ModelInfo, error) {
		args := jujuparams.ModelCreateArgs{
			Name:               petname.Generate(2, "-"),
			Qualifier:          bobOwnerTag.Id(),
			CloudTag:           names.NewCloudTag(jimmtest.TestE2ECloudName).String(),
			CloudCredentialTag: s.BobCredential.ResourceTag().String(),
		}
		var info jujuparams.ModelInfo
		err := conn.APICall(c.Context(), "ModelManager", 11, "", "CreateModel", args, &info)
		return info, err
	}

	// hostingControllerMajor returns the agent major version of the
	// controller hosting the model, straight from JIMM's database.
	hostingControllerMajor := func(c *qt.C, uuid string) int {
		m := dbmodel.Model{
			UUID: sql.NullString{String: uuid, Valid: true},
		}
		err := s.JIMM.Database.GetModel(c.Context(), &m)
		c.Assert(err, qt.IsNil)
		v, err := version.Parse(m.Controller.AgentVersion)
		c.Assert(err, qt.IsNil)
		return v.Major
	}

	// assertConstrainedPlacement asserts the spec's behavior for a client
	// treated as Juju 3.6: the model lands on a <=3.x controller when one is
	// available, and the create fails with a clear error otherwise.
	assertConstrainedPlacement := func(c *qt.C, conn api.Connection) {
		info, err := createModel(c, conn)
		if !has3x {
			c.Assert(err, qt.ErrorMatches,
				"no controller compatible with your Juju client is available; please upgrade your client to use the available controllers.*")
			return
		}
		c.Assert(err, qt.IsNil)
		c.Cleanup(func() { s.DestroyModelAndDeleteFromDatabase(c, names.NewModelTag(info.UUID)) })
		c.Check(hostingControllerMajor(c, info.UUID) <= 3, qt.IsTrue,
			qt.Commentf("model for a 3.6-treated client landed on a controller of major > 3"))
	}

	c.Run("unversioned client is treated as Juju 3.6", func(c *qt.C) {
		conn := s.OpenNoClientVersion(c, nil, bobOwnerTag.Id(), nil)
		defer conn.Close()
		assertConstrainedPlacement(c, conn)
	})

	c.Run("client reporting 3.6 is placed on a 3.x controller", func(c *qt.C) {
		conn := s.OpenWithDialWebsocket(c, nil, bobOwnerTag.Id(),
			jimmtest.DialWebsocketWithClientVersion("3.6.8"))
		defer conn.Close()
		assertConstrainedPlacement(c, conn)
	})

	c.Run("client reporting 4.x may be placed on any controller", func(c *qt.C) {
		conn := s.OpenWithDialWebsocket(c, nil, bobOwnerTag.Id(),
			jimmtest.DialWebsocketWithClientVersion("4.0.2"))
		defer conn.Close()

		info, err := createModel(c, conn)
		c.Assert(err, qt.IsNil)
		c.Cleanup(func() { s.DestroyModelAndDeleteFromDatabase(c, names.NewModelTag(info.UUID)) })
		c.Check(hostingControllerMajor(c, info.UUID) <= 4, qt.IsTrue)
	})
}
