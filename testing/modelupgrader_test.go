// Copyright 2026 Canonical.

package testing

import (
	"testing"

	petname "github.com/dustinkirkland/golang-petname"
	qt "github.com/frankban/quicktest"
	"github.com/juju/juju/api/client/modelupgrader"
	"github.com/juju/juju/core/semversion"
	jujuparams "github.com/juju/juju/rpc/params"
	"github.com/juju/names/v6"

	"github.com/canonical/jimm/v3/internal/testutils/jimmtest"
)

func TestUpgradeModelDryRun(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()

	client := modelupgrader.NewClient(conn)
	chosenVersion, err := client.UpgradeModel(t.Context(), model.UUID.String, semversion.Zero, "", false, true)
	c.Assert(err, qt.IsNil)
	c.Assert(chosenVersion, qt.Not(qt.Equals), semversion.Zero)
}

func TestUpgradeModel(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	// Create a reference model to discover the controller's current agent semversion.
	refModel := s.CreateModelForBob(c)
	ctrlVersion := semversion.MustParse(refModel.Controller.AgentVersion)
	if ctrlVersion.Patch == 0 {
		c.Skip("controller patch version is 0, cannot create a model at a lower patch version")
	}
	lowerVersion := semversion.Number{
		Major: ctrlVersion.Major,
		Minor: ctrlVersion.Minor,
		Patch: ctrlVersion.Patch - 1,
	}

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()

	// Create a model pinned to a lower agent version so there is something to upgrade.
	var mi jujuparams.ModelInfo
	err := conn.APICall(t.Context(), "ModelManager", 10, "", "CreateModel", jujuparams.ModelCreateArgs{
		Name:               petname.Generate(2, "-"),
		Qualifier:          "bob@canonical.com",
		CloudTag:           names.NewCloudTag(jimmtest.TestE2ECloudName).String(),
		CloudRegion:        jimmtest.TestE2ECloudRegionName,
		CloudCredentialTag: "cloudcred-" + jimmtest.TestE2ECloudName + "_bob@canonical.com_cred",
		Config: map[string]any{
			"agent-version": lowerVersion.String(),
		},
	}, &mi)
	c.Assert(err, qt.IsNil)
	c.Cleanup(func() {
		s.DestroyModelAndDeleteFromDatabase(c, names.NewModelTag(mi.UUID))
	})

	// Upgrade the model to the current controller semversion.
	upgradeClient := modelupgrader.NewClient(conn)
	result, err := upgradeClient.UpgradeModel(t.Context(), mi.UUID, ctrlVersion, "", false, false)
	c.Assert(err, qt.IsNil)
	c.Assert(result, qt.Equals, ctrlVersion)
}

func TestUpgradeModelCrossMajor(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)
	ctrlVersion := semversion.MustParse(model.Controller.AgentVersion)

	nextMajorVersion := semversion.Number{
		Major: ctrlVersion.Major + 1,
	}

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()

	client := modelupgrader.NewClient(conn)
	// Attempting to upgrade to a version beyond the controller's version is rejected
	// by the backing controller with the message below.
	_, err := client.UpgradeModel(t.Context(), model.UUID.String, nextMajorVersion, "", false, false)
	c.Assert(err, qt.ErrorMatches, `.*cannot upgrade to a version .* greater than that of the controller .*`)
}

func TestUpgradeModelUnauthorized(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	// Charlie owns the model; bob only has read access.
	model := s.CreateModelForCharlieWithBobReadAccess(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()

	client := modelupgrader.NewClient(conn)
	_, err := client.UpgradeModel(t.Context(), model.UUID.String, semversion.Zero, "", false, true)
	c.Assert(err, qt.ErrorMatches, `.*unauthorized.*`)
}

func TestAbortModelUpgrade(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()

	client := modelupgrader.NewClient(conn)
	err := client.AbortModelUpgrade(t.Context(), model.UUID.String)
	c.Assert(err, qt.IsNil)
}

func TestAbortModelUpgradeUnauthorized(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	// Charlie owns the model; bob only has read access.
	model := s.CreateModelForCharlieWithBobReadAccess(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()

	client := modelupgrader.NewClient(conn)
	err := client.AbortModelUpgrade(t.Context(), model.UUID.String)
	c.Assert(err, qt.ErrorMatches, `.*unauthorized.*`)
}
