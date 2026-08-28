// Copyright 2026 Canonical.

package testing

import (
	"database/sql"
	"fmt"
	"testing"

	petname "github.com/dustinkirkland/golang-petname"
	qt "github.com/frankban/quicktest"
	jujuversion "github.com/juju/juju/core/version"
	jujuparams "github.com/juju/juju/rpc/params"
	"github.com/juju/names/v6"

	"github.com/canonical/jimm/v3/internal/dbmodel"
	"github.com/canonical/jimm/v3/internal/testutils/jimmtest"
	apiparams "github.com/canonical/jimm/v3/pkg/api/params"
)

// TestNativeClientVersionHeader verifies the full released-client header
// path end to end: the juju api client jimm embeds (a released 4.x
// dependency) dials JIMM with its own websocket dialer — no test override —
// so the X-Juju-ClientVersion header on the main API dial is produced by
// the same code path a released 4.x CLI uses, and JIMM's placement and
// proxy decisions act on it.
//
// The remaining spec scenarios are covered elsewhere with an explicitly
// headerless dialer (faithful to a 3.6 CLI, which sends no header):
// placement capping in TestModelPlacementByClientVersion and proxy
// gating/unfiltered discovery in TestModelProxyClientCompatibility*.
func TestNativeClientVersionHeader(t *testing.T) {
	c := qt.New(t)

	// The premise of the native path: the embedded dependency is a
	// released 4.x client library.
	c.Assert(jujuversion.Current.Major >= 4, qt.IsTrue,
		qt.Commentf("embedded juju client version %s is not 4.x", jujuversion.Current))

	s := jimmtest.SetupJimmWithControllers(c)

	c.Run("native dial pins a model to a 4.x controller", func(c *qt.C) {
		fleet4 := backingControllersMatching(c, s, func(major int) bool { return major >= 4 })
		if len(fleet4) == 0 {
			c.Skip("no Juju 4.x backing controller in the environment")
		}
		target := fleet4[0]

		args := apiparams.AddModelToControllerRequest{
			ModelCreateArgs: jujuparams.ModelCreateArgs{
				Name:               petname.Generate(2, "-"),
				Qualifier:          bobOwnerTag.Id(),
				CloudTag:           names.NewCloudTag(jimmtest.TestE2ECloudName).String(),
				CloudCredentialTag: s.BobCredential.ResourceTag().String(),
			},
			ControllerName: target.name,
		}

		// A headerless (3.6) client may not use the 4.x controller: proves
		// the placement gate is active for this exact request.
		headerless := s.OpenNoClientVersion(c, nil, bobOwnerTag.Id(), nil)
		defer headerless.Close()
		var mi jujuparams.ModelInfo
		err := headerless.APICall(c.Context(), "JIMM", 4, "", "AddModelToController", args, &mi)
		c.Assert(err, qt.ErrorMatches,
			fmt.Sprintf(`.*controller %q \(version %q\) is not compatible with your Juju client; please upgrade your client to use this controller.*`,
				target.name, target.agent))

		// The same request over a native dial succeeds — possible only if
		// juju's own dialer delivered the version header to JIMM.
		conn := s.Open(c, nil, bobOwnerTag.Id(), nil)
		defer conn.Close()
		err = conn.APICall(c.Context(), "JIMM", 4, "", "AddModelToController", args, &mi)
		c.Assert(err, qt.IsNil)
		c.Cleanup(func() { s.DestroyModelAndDeleteFromDatabase(c, names.NewModelTag(mi.UUID)) })

		model := dbmodel.Model{
			UUID: sql.NullString{String: mi.UUID, Valid: true},
		}
		err = s.JIMM.Database.GetModel(c.Context(), &model)
		c.Assert(err, qt.IsNil)
		c.Check(model.Controller.Name, qt.Equals, target.name)
	})

	c.Run("native client reaches models hosted on every controller", func(c *qt.C) {
		fleet := backingControllersMatching(c, s, func(int) bool { return true })
		c.Assert(fleet, qt.Not(qt.HasLen), 0)
		for _, ctl := range fleet {
			c.Run(fmt.Sprintf("model hosted on %s (%s)", ctl.name, ctl.agent), func(c *qt.C) {
				model := createModelOn(c, s, ctl.name)
				mt := model.ResourceTag()

				conn, err := s.OpenNoAssert(c, jimmtest.LoginDetails{Username: bobOwnerTag.Id()}, &mt)
				c.Assert(err, qt.IsNil)
				defer conn.Close()
				err = conn.APICall(c.Context(), "Pinger", 1, "", "Ping", nil, nil)
				c.Check(err, qt.IsNil)
			})
		}
	})
}
