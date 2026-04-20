// Copyright 2026 Canonical.

package testing

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/juju/description/v12"
	"github.com/juju/juju/api/controller/migrationtarget"
	"github.com/juju/juju/core/migration"
	coremodel "github.com/juju/juju/core/model"
	"github.com/juju/juju/core/semversion"
	jujuparams "github.com/juju/juju/rpc/params"
	"github.com/juju/names/v6"

	"github.com/canonical/jimm/v3/internal/testutils/jimmtest"
	"github.com/canonical/jimm/v3/pkg/api"
	"github.com/canonical/jimm/v3/pkg/api/params"
)

func TestAbort(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	conn := s.Open(c, nil, "alice", nil)
	defer conn.Close()

	modelUUID := "00000001-0000-0000-0000-000000000001"
	client := migrationtarget.NewClient(conn)
	err := client.Abort(t.Context(), modelUUID)
	c.Assert(err, qt.ErrorMatches, `.*model migration not found.*`)
}

func TestCheckMachines(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	conn := s.Open(c, nil, "alice", nil)
	defer conn.Close()

	modelUUID := "00000001-0000-0000-0000-000000000001"
	client := migrationtarget.NewClient(conn)
	_, err := client.CheckMachines(t.Context(), modelUUID)
	c.Assert(err, qt.ErrorMatches, `.*model migration not found.*`)
}

func TestPrechecks(t *testing.T) {
	// We need to skip this test because calling api.Precheck() fills the FacadeVersion in the args with
	// api.SupportedVersion() which is just fetching the version for the facade the client requires.
	// Now we only support migrating 3 models, but the `api` package comes from Juju 4.
	// So this test will always fail because the FacadeVersions will never be accepted by the
	// target Juju 3 controller.
	// Once we support the migration of Juju 4 models, we can re-enable this test.
	t.Skip()
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	conn := s.Open(c, nil, "alice", nil)
	defer conn.Close()

	cct := names.NewCloudCredentialTag(jimmtest.TestE2ECloudName + "/alice@canonical.com/cred")
	s.UpdateCloudCredential(c, cct, jujuparams.CloudCredential{
		AuthType: "empty",
	})

	modelDescriptionArgs := description.ModelArgs{
		Type:        description.IAAS,
		Owner:       "alice",
		Cloud:       jimmtest.TestE2ECloudName,
		CloudRegion: jimmtest.TestE2ECloudRegionName,
	}
	modelUUID := "00000001-0000-0000-0000-000000000001"
	modelDescription := description.NewModel(modelDescriptionArgs)
	modelDescription.SetCloudCredential(description.CloudCredentialArgs{
		Name:  "cred",
		Cloud: jimmtest.TestE2ECloudName,
		Owner: "alice",
	})
	model := migration.ModelInfo{
		UUID:                   modelUUID,
		Qualifier:              coremodel.Qualifier("alice"),
		Name:                   "test-model",
		ControllerAgentVersion: semversion.MustParse("3.6.9"),
		AgentVersion:           semversion.MustParse("3.6.9"),
		ModelDescription:       modelDescription,
	}
	client := migrationtarget.NewClient(conn)
	err := client.Prechecks(t.Context(), model)
	c.Assert(err, qt.ErrorMatches, `.*model migration not found.*`)

	controllerName, _ := s.GetOneControllerConfig(c)

	prepareModelMigration := params.PrepareModelMigrationRequest{
		ModelTag:              names.NewModelTag(modelUUID).String(),
		BackingControllerName: controllerName,
		UserMapping:           map[string]string{"alice": "alice@canonical.com"},
	}
	jimmClient := api.NewClient(conn)
	migrationToken, err := jimmClient.PrepareModelMigration(t.Context(), &prepareModelMigration)
	c.Assert(err, qt.IsNil)
	c.Assert(migrationToken, qt.Not(qt.Equals), "")

	err = client.Prechecks(t.Context(), model)
	c.Assert(err, qt.IsNil)
}

func TestCACert(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	conn := s.Open(c, nil, "alice", nil)
	defer conn.Close()

	client := migrationtarget.NewClient(conn)
	cert, err := client.CACert(t.Context())
	c.Assert(err, qt.IsNil)
	c.Assert(cert, qt.Equals, "")
}

func TestAdoptResources(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	conn := s.Open(c, nil, "alice", nil)
	defer conn.Close()

	modelUUID := "00000001-0000-0000-0000-000000000001"
	client := migrationtarget.NewClient(conn)
	err := client.AdoptResources(t.Context(), modelUUID)
	c.Assert(err, qt.ErrorMatches, `.*model not found.*`)
}

func TestActivate(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	conn := s.Open(c, nil, "alice", nil)
	defer conn.Close()

	modelUUID := "00000001-0000-0000-0000-000000000001"
	sourceInfo := migration.SourceControllerInfo{
		ControllerTag: names.NewControllerTag("00000001-0000-0000-0000-000000000002"),
	}
	relatedModels := []string{"related-model-1", "related-model-2"}

	client := migrationtarget.NewClient(conn)
	err := client.Activate(t.Context(), modelUUID, sourceInfo, relatedModels)
	c.Assert(err, qt.ErrorMatches, `.*model migration not found.*`)
}

func TestLatestLogTime(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	conn := s.Open(c, nil, "alice", nil)
	defer conn.Close()

	client := migrationtarget.NewClient(conn)
	_, err := client.LatestLogTime(t.Context(), model.UUID.String)
	c.Assert(err, qt.IsNil)
}

func TestImport(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	conn := s.Open(c, nil, "alice", nil)
	defer conn.Close()

	client := migrationtarget.NewClient(conn)
	err := client.Import(t.Context(), []byte{})
	c.Assert(err, qt.ErrorMatches, `^failed to import model.*`)
}
