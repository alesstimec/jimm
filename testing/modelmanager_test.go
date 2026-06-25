// Copyright 2025 Canonical.

package testing

import (
	"context"
	"testing"
	"time"

	petname "github.com/dustinkirkland/golang-petname"
	qt "github.com/frankban/quicktest"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juju/juju/api/base"
	"github.com/juju/juju/api/client/modelmanager"
	"github.com/juju/juju/core/life"
	coremodel "github.com/juju/juju/core/model"
	"github.com/juju/juju/core/status"
	"github.com/juju/juju/environs/config"
	jujuparams "github.com/juju/juju/rpc/params"
	"github.com/juju/names/v6"

	"github.com/canonical/jimm/v3/internal/dbmodel"
	"github.com/canonical/jimm/v3/internal/openfga"
	ofganames "github.com/canonical/jimm/v3/internal/openfga/names"
	"github.com/canonical/jimm/v3/internal/testutils/jimmtest"
)

func TestListModelSummaries(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)
	model3 := s.CreateModelForCharlieWithBobReadAccess(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()

	client := modelmanager.NewClient(conn)

	s.DeployApplication(c, s.AdminUser, model.Tag(), jimmtest.DeployApplicationParams{
		App:   "test-app",
		Charm: "juju-qa-test",
	})

	models, err := client.ListModelSummaries(t.Context(), "bob@canonical.com", true)
	c.Assert(err, qt.Equals, nil)
	c.Assert(models, qt.CmpEquals(
		cmpopts.IgnoreTypes(&time.Time{}),
		cmpopts.IgnoreFields(base.UserModelSummary{}, "AgentVersion"),
		// Ignore machine counts as they depend on timing
		cmpopts.IgnoreSliceElements(func(ec base.EntityCount) bool {
			return ec.Entity == "machines"
		}),
		cmpopts.SortSlices(func(a, b base.UserModelSummary) bool {
			return a.Name < b.Name
		}),
	), []base.UserModelSummary{{
		Name:            model.Name,
		UUID:            model.UUID.String,
		ControllerUUID:  jimmtest.ControllerUUID,
		ProviderType:    jimmtest.TestE2EProviderType,
		Cloud:           jimmtest.TestE2ECloudName,
		CloudRegion:     jimmtest.TestE2ECloudName,
		CloudCredential: jimmtest.TestE2ECloudName + "/bob@canonical.com/cred",
		Qualifier:       "bob@canonical.com",
		Life:            life.Value(string(life.Alive)),
		Status: base.Status{
			Status: status.Available,
			Data:   map[string]any{},
		},
		ModelUserAccess: "admin",
		Counts:          []base.EntityCount{{Entity: "units", Count: 1}},
		Type:            "iaas",
	}, {
		Name:            model3.Name,
		UUID:            model3.UUID.String,
		ControllerUUID:  jimmtest.ControllerUUID,
		ProviderType:    jimmtest.TestE2EProviderType,
		Cloud:           jimmtest.TestE2ECloudName,
		CloudRegion:     jimmtest.TestE2ECloudRegionName,
		CloudCredential: jimmtest.TestE2ECloudName + "/charlie@canonical.com/cred",
		Qualifier:       "charlie@canonical.com",
		Life:            life.Value(string(life.Alive)),
		Status: base.Status{
			Status: status.Available,
			Data:   map[string]any{},
		},
		ModelUserAccess: "read",
		Counts:          []base.EntityCount{},
		Type:            "iaas",
	}})
}

func TestListModelSummariesWithoutControllerUUIDMasking(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	s.CreateModelForBob(c)

	conn1 := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn1.Close()
	err := conn1.APICall(t.Context(), "JIMM", 4, "", "DisableControllerUUIDMasking", nil, nil)
	c.Assert(err, qt.ErrorMatches, `unauthorized \(unauthorized access\)`)

	conn := s.Open(c, nil, "alice@canonical.com", nil)
	defer conn.Close()

	err = conn.APICall(t.Context(), "JIMM", 4, "", "DisableControllerUUIDMasking", nil, nil)
	c.Assert(err, qt.Equals, nil)

	client := modelmanager.NewClient(conn)
	models, err := client.ListModelSummaries(t.Context(), "bob@canonical.com", false)
	c.Assert(err, qt.Equals, nil)
	c.Assert(len(models), qt.Equals, 1)
	for _, model := range models {
		c.Assert(model.ControllerUUID, qt.Not(qt.Equals), jimmtest.ControllerUUID)
	}
}

func TestListModels(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model2 := s.CreateModelForCharlie(c)
	model3 := s.CreateModelForCharlieWithBobReadAccess(c)

	conn := s.Open(c, nil, "charlie@canonical.com", nil)
	defer conn.Close()

	client := modelmanager.NewClient(conn)
	models, err := client.ListModels(t.Context(), "charlie@canonical.com")
	c.Assert(err, qt.Equals, nil)
	c.Assert(
		models,
		qt.CmpEquals(
			cmpopts.IgnoreTypes(&time.Time{}),
			cmpopts.SortSlices(func(a, b base.UserModel) bool {
				return a.Name < b.Name
			}),
		),
		[]base.UserModel{
			{
				Name:      model2.Name,
				UUID:      model2.UUID.String,
				Qualifier: "charlie@canonical.com",
				Type:      "iaas",
			}, {
				Name:      model3.Name,
				UUID:      model3.UUID.String,
				Qualifier: "charlie@canonical.com",
				Type:      "iaas",
			},
		},
	)
}

func TestModelInfo(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)
	model2 := s.CreateModelForCharlie(c)
	model3 := s.CreateModelForCharlieWithBobReadAccess(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()
	client := modelmanager.NewClient(conn)
	models, err := client.ModelInfo(t.Context(), []names.ModelTag{
		model.ResourceTag(),
		model2.ResourceTag(),
		model3.ResourceTag(),
		names.NewModelTag("00000000-0000-0000-0000-000000000007"),
	})
	c.Assert(err, qt.Equals, nil)

	// Verify we got results for all 4 model requests
	c.Assert(models, qt.HasLen, 4)

	// Helper to find user access in Users slice
	findUserAccess := func(users []jujuparams.ModelUserInfo, username string) string {
		for _, u := range users {
			if u.UserName == username {
				return string(u.Access)
			}
		}
		return ""
	}

	// Model 1 (model) - bob has admin access
	c.Assert(models[0].Error, qt.Equals, (*jujuparams.Error)(nil))
	c.Assert(models[0].Result.Name, qt.Equals, model.Name)
	c.Assert(models[0].Result.UUID, qt.Equals, model.UUID.String)
	c.Assert(models[0].Result.Life, qt.Equals, life.Alive)
	c.Assert(models[0].Result.ControllerUUID, qt.Equals, jimmtest.ControllerUUID)
	c.Assert(models[0].Result.CloudCredentialTag, qt.Equals, model.CloudCredential.Tag().String())
	c.Assert(models[0].Result.Qualifier, qt.Equals, "bob@canonical.com")
	// As admin, bob can see all users
	c.Assert(findUserAccess(models[0].Result.Users, "bob@canonical.com"), qt.Equals, "admin")
	c.Assert(findUserAccess(models[0].Result.Users, "alice@canonical.com"), qt.Equals, "admin")

	// Model 2 (model2) - bob has no access
	c.Assert(models[1].Result, qt.IsNil)
	c.Assert(models[1].Error, qt.Not(qt.IsNil))
	c.Assert(models[1].Error.Code, qt.Equals, jujuparams.CodeUnauthorized)

	// Model 3 (model3) - bob has read access
	c.Assert(models[2].Error, qt.Equals, (*jujuparams.Error)(nil))
	c.Assert(models[2].Result.Name, qt.Equals, model3.Name)
	c.Assert(models[2].Result.UUID, qt.Equals, model3.UUID.String)
	c.Assert(models[2].Result.ControllerUUID, qt.Equals, jimmtest.ControllerUUID)
	c.Assert(models[2].Result.CloudCredentialTag, qt.Equals, model3.CloudCredential.Tag().String())
	c.Assert(models[2].Result.Qualifier, qt.Equals, "charlie@canonical.com")
	// As reader, bob can only see himself in users list
	c.Assert(findUserAccess(models[2].Result.Users, "bob@canonical.com"), qt.Equals, "read")
	// Read access means no machines visible
	c.Assert(models[2].Result.Machines, qt.IsNil)

	// Non-existent model - unauthorized
	c.Assert(models[3].Result, qt.IsNil)
	c.Assert(models[3].Error, qt.Not(qt.IsNil))
	c.Assert(models[3].Error.Code, qt.Equals, jujuparams.CodeUnauthorized)
}

func TestModelInfoDisableControllerUUIDMasking(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	// Make bob a JIMM administrator so he can disable UUID masking
	err := s.OFGAClient.AddRelation(context.Background(),
		openfga.Tuple{
			Object:   ofganames.ConvertTag(names.NewUserTag("bob@canonical.com")),
			Relation: ofganames.AdministratorRelation,
			Target:   ofganames.ConvertTag(s.JIMM.ResourceTag()),
		},
	)
	c.Assert(err, qt.Equals, nil)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()

	// Disable controller UUID masking
	err = conn.APICall(t.Context(), "JIMM", 4, "", "DisableControllerUUIDMasking", nil, nil)
	c.Assert(err, qt.Equals, nil)

	client := modelmanager.NewClient(conn)
	models, err := client.ModelInfo(t.Context(), []names.ModelTag{model.ResourceTag()})
	c.Assert(err, qt.Equals, nil)
	c.Assert(models, qt.HasLen, 1)
	c.Assert(models[0].Error, qt.Equals, (*jujuparams.Error)(nil))

	// The controller UUID should NOT be the masked JIMM controller UUID
	c.Assert(models[0].Result.ControllerUUID, qt.Not(qt.Equals), jimmtest.ControllerUUID)
	// It should be the actual backing controller's UUID
	c.Assert(models[0].Result.ControllerUUID, qt.Not(qt.Equals), "")
}

func TestCreateModel(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()

	// Generate unique model names for each test
	generateModelName := func() string {
		return petname.Generate(2, "-")
	}

	createModelTests := []struct {
		about         string
		name          string
		owner         string
		region        string
		cloud         string
		credentialTag names.CloudCredentialTag
		config        map[string]any
		expectError   string
	}{{
		about:         "success",
		name:          generateModelName(),
		owner:         "bob@canonical.com",
		cloud:         jimmtest.TestE2ECloudName,
		credentialTag: names.NewCloudCredentialTag(jimmtest.TestE2ECloudName + "/bob@canonical.com/cred"),
	}, {
		about:         "unauthorized user",
		name:          generateModelName(),
		owner:         "noauthuser@canonical.com",
		cloud:         jimmtest.TestE2ECloudName,
		credentialTag: names.NewCloudCredentialTag(jimmtest.TestE2ECloudName + "/bob@canonical.com/cred"),
		expectError:   `unauthorized \(unauthorized access\)`,
	}, {
		about:         "existing model name",
		name:          model.Name, // Use existing model name to trigger duplicate error
		owner:         "bob@canonical.com",
		cloud:         jimmtest.TestE2ECloudName,
		credentialTag: names.NewCloudCredentialTag(jimmtest.TestE2ECloudName + "/bob@canonical.com/cred"),
		expectError:   "model bob@canonical.com/" + model.Name + " already exists \\(already exists\\)",
	}, {
		about:       "no controller for region",
		name:        generateModelName(),
		owner:       "bob@canonical.com",
		region:      "no-such-region",
		cloud:       jimmtest.TestE2ECloudName,
		expectError: `cloud region "no-such-region" not found in cloud "localhost" \(not found\)`,
	}, {
		about:         "local user",
		name:          generateModelName(),
		owner:         "bob",
		cloud:         jimmtest.TestE2ECloudName,
		credentialTag: names.NewCloudCredentialTag(jimmtest.TestE2ECloudName + "/bob@canonical.com/cred"),
		expectError:   `unauthorized \(unauthorized access\)`,
	}, {
		about:         "specific cloud",
		name:          generateModelName(),
		owner:         "bob@canonical.com",
		cloud:         jimmtest.TestE2ECloudName,
		credentialTag: names.NewCloudCredentialTag(jimmtest.TestE2ECloudName + "/bob@canonical.com/cred"),
	}, {
		about:         "specific cloud and region",
		name:          generateModelName(),
		owner:         "bob@canonical.com",
		cloud:         jimmtest.TestE2ECloudName,
		region:        jimmtest.TestE2ECloudRegionName,
		credentialTag: names.NewCloudCredentialTag(jimmtest.TestE2ECloudName + "/bob@canonical.com/cred"),
	}, {
		about:         "bad cloud tag",
		name:          generateModelName(),
		owner:         "bob@canonical.com",
		cloud:         "not-a-cloud-tag",
		credentialTag: names.NewCloudCredentialTag(jimmtest.TestE2ECloudName + "/bob@canonical.com/cred"),
		expectError:   `cloud credential cloud mismatch`,
	}, {
		about:  "no credential tag selects unambiguous creds",
		name:   generateModelName(),
		owner:  "bob@canonical.com",
		cloud:  jimmtest.TestE2ECloudName,
		region: jimmtest.TestE2ECloudRegionName,
	}, {
		about:         "success - without a cloud tag",
		name:          generateModelName(),
		owner:         "bob@canonical.com",
		credentialTag: names.NewCloudCredentialTag(jimmtest.TestE2ECloudName + "/bob@canonical.com/cred"),
	}}

	for i, test := range createModelTests {
		c.Logf("test %d. %s", i, test.about)
		client := modelmanager.NewClient(conn)
		mi, err := client.CreateModel(t.Context(), test.name, names.NewUserTag(test.owner), test.cloud, test.region, test.credentialTag, test.config)
		if test.expectError != "" {
			c.Assert(err, qt.ErrorMatches, test.expectError)
			continue
		}
		c.Assert(err, qt.Equals, nil)
		c.Assert(mi.Name, qt.Equals, test.name)
		c.Assert(mi.UUID, qt.Not(qt.Equals), "")
		c.Assert(mi.Qualifier, qt.Equals, coremodel.Qualifier(test.owner))
		c.Assert(mi.ControllerUUID, qt.Equals, jimmtest.ControllerUUID)
		c.Assert(mi.Users, qt.Not(qt.HasLen), 0)
		emptyCred := names.CloudCredentialTag{}
		if test.credentialTag == emptyCred {
			c.Assert(mi.CloudCredential, qt.Not(qt.Equals), "")
		} else {
			c.Assert(mi.CloudCredential, qt.Equals, test.credentialTag.Id())
		}
		if test.cloud == "" {
			c.Assert(mi.Cloud, qt.Equals, jimmtest.TestE2ECloudName)
		} else {
			c.Assert(mi.Cloud, qt.Equals, test.cloud)
		}
	}
}

func TestCreateDuplicateModelsFails(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()
	client := modelmanager.NewClient(conn)

	modelName := petname.Generate(2, "-")
	createModel := func() error {
		_, err := client.CreateModel(
			t.Context(),
			modelName,
			names.NewUserTag("bob@canonical.com"),
			jimmtest.TestE2ECloudName,
			"",
			names.NewCloudCredentialTag(jimmtest.TestE2ECloudName+"/bob@canonical.com/cred"),
			nil,
		)
		return err
	}
	err := createModel()
	c.Assert(err, qt.IsNil)
	err = createModel()
	c.Assert(err, qt.ErrorMatches, `model bob@canonical\.com/`+modelName+` already exists \(already exists\)`)
}

func TestGrantAndRevokeModel(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()
	client := modelmanager.NewClient(conn)

	conn2 := s.Open(c, nil, "charlie@canonical.com", nil)
	defer conn2.Close()
	client2 := modelmanager.NewClient(conn2)

	res, err := client2.ModelInfo(t.Context(), []names.ModelTag{model.ResourceTag()})
	c.Assert(err, qt.Equals, nil)
	c.Assert(res, qt.HasLen, 1)
	c.Assert(res[0].Error, qt.ErrorMatches, "unauthorized")

	err = client.GrantModel(t.Context(), "charlie@canonical.com", "write", model.UUID.String)
	c.Assert(err, qt.Equals, nil)

	res, err = client2.ModelInfo(t.Context(), []names.ModelTag{model.ResourceTag()})
	c.Assert(err, qt.Equals, nil)
	c.Assert(res, qt.HasLen, 1)
	c.Assert(res[0].Error, qt.Equals, (*jujuparams.Error)(nil))
	c.Assert(res[0].Result.UUID, qt.Equals, model.UUID.String)

	err = client.RevokeModel(t.Context(), "charlie@canonical.com", "read", model.UUID.String)
	c.Assert(err, qt.Equals, nil)

	res, err = client2.ModelInfo(t.Context(), []names.ModelTag{model.ResourceTag()})
	c.Assert(err, qt.Equals, nil)
	c.Assert(res, qt.HasLen, 1)
	c.Assert(res[0].Error, qt.Not(qt.IsNil))
	c.Assert(res[0].Error, qt.ErrorMatches, "unauthorized")
}

func TestUserCannotRevokeOwnAccessWithoutAdmin(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()
	client := modelmanager.NewClient(conn)

	conn2 := s.Open(c, nil, "charlie@canonical.com", nil)
	defer conn2.Close()
	client2 := modelmanager.NewClient(conn2)

	err := client.GrantModel(t.Context(), "charlie@canonical.com", "read", model.UUID.String)
	c.Assert(err, qt.Equals, nil)

	res, err := client2.ModelInfo(t.Context(), []names.ModelTag{names.NewModelTag(model.UUID.String)})
	c.Assert(err, qt.Equals, nil)
	c.Assert(res, qt.HasLen, 1)
	c.Assert(res[0].Error, qt.Equals, (*jujuparams.Error)(nil))
	c.Assert(res[0].Result.UUID, qt.Equals, model.UUID.String)

	err = client2.RevokeModel(t.Context(), "charlie@canonical.com", "read", model.UUID.String)
	c.Assert(err, qt.ErrorMatches, "unauthorized")

	res, err = client2.ModelInfo(t.Context(), []names.ModelTag{names.NewModelTag(model.UUID.String)})
	c.Assert(err, qt.Equals, nil)
	c.Assert(res, qt.HasLen, 1)
	c.Assert(res[0].Error, qt.Equals, (*jujuparams.Error)(nil))
	c.Assert(res[0].Result.UUID, qt.Equals, model.UUID.String)
}

func TestModifyModelAccessErrors(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)
	model2 := s.CreateModelForCharlie(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()
	client := modelmanager.NewClient(conn)

	modifyModelAccessErrorTests := []struct {
		about       string
		user        string
		access      string
		modelUUID   string
		expectError string
	}{{
		about:       "unauthorized",
		user:        "eve@canonical.com",
		access:      "read",
		modelUUID:   model2.UUID.String,
		expectError: `unauthorized`,
	}, {
		about:       "bad user domain",
		user:        "eve@local",
		access:      "read",
		modelUUID:   model.UUID.String,
		expectError: `unsupported local user; if this is a service account add @serviceaccount domain`,
	}, {
		about:       "no such model",
		user:        "eve@canonical.com",
		access:      "read",
		modelUUID:   "00000000-0000-0000-0000-000000000000",
		expectError: `unauthorized`,
	}, {
		about:       "invalid model uuid",
		user:        "eve@canonical.com",
		access:      "read",
		modelUUID:   "not-a-model-uuid",
		expectError: `invalid model: "not-a-model-uuid"`,
	}, {
		about:       "invalid username",
		user:        "not-a-user-tag",
		access:      "read",
		modelUUID:   model.UUID.String,
		expectError: `unsupported local user; if this is a service account add @serviceaccount domain`,
	}, {
		about:       "invalid access",
		user:        "eve@canonical.com",
		access:      "not-an-access",
		modelUUID:   model.UUID.String,
		expectError: `.*not-an-access.*`,
	}}

	for i, test := range modifyModelAccessErrorTests {
		c.Logf("%d. %s", i, test.about)
		err := client.GrantModel(t.Context(), test.user, test.access, test.modelUUID)
		c.Assert(err, qt.ErrorMatches, test.expectError)
	}
}

var zeroDuration = time.Duration(0)

func TestDestroyModel(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	// Create a new model to destroy so we don't affect other tests
	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()
	client := modelmanager.NewClient(conn)

	modelName := petname.Generate(2, "-")
	mi, err := client.CreateModel(
		t.Context(),
		modelName,
		names.NewUserTag("bob@canonical.com"),
		jimmtest.TestE2ECloudName,
		"",
		names.NewCloudCredentialTag(jimmtest.TestE2ECloudName+"/bob@canonical.com/cred"),
		nil,
	)
	c.Assert(err, qt.Equals, nil)

	tag := names.NewModelTag(mi.UUID)
	err = client.DestroyModel(t.Context(), tag, nil, nil, nil, &zeroDuration)
	c.Assert(err, qt.Equals, nil)

	// Check the model is now dying.
	mis, err := client.ModelInfo(t.Context(), []names.ModelTag{tag})
	c.Assert(err, qt.Equals, nil)
	c.Assert(mis, qt.HasLen, 1)
	c.Assert(mis[0].Error, qt.Equals, (*jujuparams.Error)(nil))
	c.Assert(mis[0].Result.Life == life.Dying || mis[0].Result.Life == life.Dead, qt.IsTrue)

	// Make sure it's not an error if you destroy a model that's not there.
	err = client.DestroyModel(t.Context(), tag, nil, nil, nil, &zeroDuration)
	c.Assert(err, qt.Equals, nil)
}

func TestDumpModel(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()

	tag := model.ResourceTag()
	client := modelmanager.NewClient(conn)
	res, err := client.DumpModel(t.Context(), tag)
	c.Check(err, qt.Equals, nil)
	c.Check(res, qt.Not(qt.HasLen), 0)
}

func TestDumpModelUnauthorized(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	conn := s.Open(c, nil, "charlie@canonical.com", nil)
	defer conn.Close()

	tag := model.ResourceTag()
	client := modelmanager.NewClient(conn)
	res, err := client.DumpModel(t.Context(), tag)
	c.Check(err, qt.ErrorMatches, `unauthorized`)
	c.Check(res, qt.IsNil)
}

func TestDumpModelDB(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	SkipIfControllerAgentVersionGreaterThan(c, model.Controller.AgentVersion, "4.0.0")
	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()

	tag := model.ResourceTag()
	client := modelmanager.NewClient(conn)
	res, err := client.DumpModelDB(t.Context(), tag)
	c.Check(err, qt.Equals, nil)
	c.Check(res, qt.Not(qt.HasLen), 0)
}

func TestDumpModelDBUnauthorized(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	conn := s.Open(c, nil, "charlie@canonical.com", nil)
	defer conn.Close()

	tag := model.ResourceTag()
	client := modelmanager.NewClient(conn)
	res, err := client.DumpModelDB(t.Context(), tag)
	c.Check(err, qt.ErrorMatches, `unauthorized`)
	c.Check(res, qt.IsNil)
}

func TestChangeModelCredential(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()

	modelTag := model.ResourceTag()
	credTag := names.NewCloudCredentialTag(jimmtest.TestE2ECloudName + "/bob@canonical.com/cred2")
	cred := s.GetExistingClientCredentialsForCloud(c, jimmtest.TestE2ECloudName)
	s.UpdateCloudCredential(c, credTag, cred)
	client := modelmanager.NewClient(conn)
	err := client.ChangeModelCredential(t.Context(), modelTag, credTag)
	c.Assert(err, qt.Equals, nil)
	mir, err := client.ModelInfo(t.Context(), []names.ModelTag{modelTag})
	c.Assert(err, qt.Equals, nil)
	c.Assert(mir, qt.HasLen, 1)
	c.Assert(mir[0].Error, qt.Equals, (*jujuparams.Error)(nil))
	c.Assert(mir[0].Result.CloudCredentialTag, qt.Equals, credTag.String())
}

func TestChangeModelCredentialUnauthorizedModel(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	conn := s.Open(c, nil, "charlie@canonical.com", nil)
	defer conn.Close()

	modelTag := model.ResourceTag()
	credTag := names.NewCloudCredentialTag(jimmtest.TestE2ECloudName + "/bob@canonical.com/cred2")
	client := modelmanager.NewClient(conn)
	err := client.ChangeModelCredential(t.Context(), modelTag, credTag)
	c.Assert(err, qt.ErrorMatches, `unauthorized`)
}

func TestChangeModelCredentialUnauthorizedCredential(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()

	modelTag := model.ResourceTag()
	credTag := names.NewCloudCredentialTag(jimmtest.TestE2ECloudName + "/alice@canonical.com/cred2")
	client := modelmanager.NewClient(conn)
	err := client.ChangeModelCredential(t.Context(), modelTag, credTag)
	c.Assert(err, qt.ErrorMatches, `unauthorized`)
}

func TestChangeModelCredentialNotFoundModel(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()

	modelTag := names.NewModelTag("00000000-0000-0000-0000-000000000000")
	credTag := model.CloudCredential.ResourceTag()
	client := modelmanager.NewClient(conn)
	err := client.ChangeModelCredential(t.Context(), modelTag, credTag)
	c.Assert(err, qt.ErrorMatches, `model not found`)
}

func TestChangeModelCredentialNotFoundCredential(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()

	modelTag := model.ResourceTag()
	credTag := names.NewCloudCredentialTag(jimmtest.TestE2ECloudName + "/bob@canonical.com/cred2")
	client := modelmanager.NewClient(conn)
	err := client.ChangeModelCredential(t.Context(), modelTag, credTag)
	c.Assert(err, qt.ErrorMatches, `cloudcredential "`+jimmtest.TestE2ECloudName+`/bob@canonical.com/cred2" not found`)
}

func TestChangeModelCredentialLocalUserCredential(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()

	modelTag := model.ResourceTag()
	credTag := names.NewCloudCredentialTag(jimmtest.TestE2ECloudName + "/bob/cred2")
	client := modelmanager.NewClient(conn)
	err := client.ChangeModelCredential(t.Context(), modelTag, credTag)
	c.Assert(err, qt.ErrorMatches, `unauthorized`)
}

func TestModelDefaults(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	err := s.JIMM.Database.AddCloud(context.Background(), &dbmodel.Cloud{
		Name: "aws",
		Type: "ec2",
		Regions: []dbmodel.CloudRegion{{
			Name: "eu-central-1",
		}, {
			Name: "eu-central-2",
		}},
	})
	c.Assert(err, qt.IsNil)

	conn := s.Open(c, nil, "alice@canonical.com", nil)
	defer conn.Close()
	client := modelmanager.NewClient(conn)

	err = client.SetModelDefaults(t.Context(), "aws", "eu-central-1", map[string]any{
		"a": 1,
		"b": "value1",
	})
	c.Assert(err, qt.IsNil)
	err = client.SetModelDefaults(t.Context(), "aws", "eu-central-2", map[string]any{
		"b": "value2",
		"c": 17,
	})
	c.Assert(err, qt.IsNil)

	values, err := client.ModelDefaults(t.Context(), "aws")
	c.Assert(err, qt.IsNil)
	c.Assert(values, qt.DeepEquals, config.ModelDefaultAttributes{
		"a": config.AttributeDefaultValues{
			Regions: []config.RegionDefaultValue{{
				Name:  "eu-central-1",
				Value: float64(1),
			}},
		},
		"b": config.AttributeDefaultValues{
			Regions: []config.RegionDefaultValue{{
				Name:  "eu-central-1",
				Value: "value1",
			}, {
				Name:  "eu-central-2",
				Value: "value2",
			}},
		},
		"c": config.AttributeDefaultValues{
			Regions: []config.RegionDefaultValue{{
				Name:  "eu-central-2",
				Value: float64(17),
			}},
		},
	})

	err = client.UnsetModelDefaults(t.Context(), "aws", "eu-central-1", "b", "c")
	c.Assert(err, qt.IsNil)

	err = client.UnsetModelDefaults(t.Context(), "aws", "eu-central-2", "a", "b")
	c.Assert(err, qt.IsNil)

	values, err = client.ModelDefaults(t.Context(), "aws")
	c.Assert(err, qt.IsNil)
	c.Assert(values, qt.DeepEquals, config.ModelDefaultAttributes{
		"a": config.AttributeDefaultValues{
			Regions: []config.RegionDefaultValue{{
				Name:  "eu-central-1",
				Value: float64(1),
			}},
		},
		"c": config.AttributeDefaultValues{
			Regions: []config.RegionDefaultValue{{
				Name:  "eu-central-2",
				Value: float64(17),
			}},
		},
	})

	conn1 := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn1.Close()
	client1 := modelmanager.NewClient(conn1)

	values, err = client1.ModelDefaults(t.Context(), "aws")
	c.Assert(err, qt.IsNil)
	c.Assert(values, qt.DeepEquals, config.ModelDefaultAttributes{})
}
