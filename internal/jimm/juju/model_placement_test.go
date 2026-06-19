// Copyright 2026 Canonical.

package juju_test

import (
	"context"
	"database/sql"
	"testing"

	qt "github.com/frankban/quicktest"
	jujuparams "github.com/juju/juju/rpc/params"
	"github.com/juju/names/v6"

	"github.com/canonical/jimm/v3/internal/dbmodel"
	"github.com/canonical/jimm/v3/internal/jimm/juju"
	"github.com/canonical/jimm/v3/internal/openfga"
	"github.com/canonical/jimm/v3/internal/testutils/jimmtest"
)

// TestAddModelControllerVersionPlacement verifies that AddModel honours the
// MaxControllerMajorVersion constraint (set for Juju 3.6 clients): the new
// model is placed only on a controller whose agent major version is within the
// constraint, and a request that cannot be satisfied fails with a clear error.
//
// The controllers' agent versions are set directly in the test environment, so
// the placement decision is exercised deterministically without bootstrapping
// real controllers of specific versions.
func TestAddModelControllerVersionPlacement(t *testing.T) {
	c := qt.New(t)

	// A two-controller fleet serving the same cloud/region. controller-40 (a
	// 4.x controller) has the higher placement priority, so it is preferred
	// when no version constraint applies; controller-36 is a 3.6 controller.
	mixedFleetEnv := `
clouds:
- name: test-cloud
  type: test-provider
  regions:
  - name: test-region-1
  users:
  - user: alice@canonical.com
    access: add-model
cloud-credentials:
- name: test-credential-1
  owner: alice@canonical.com
  cloud: test-cloud
  auth-type: empty
controllers:
- name: controller-40
  uuid: 00000000-0000-0000-0000-000000000040
  cloud: test-cloud
  region: test-region-1
  agent-version: "4.0.2"
  cloud-regions:
  - cloud: test-cloud
    region: test-region-1
    priority: 10
  users:
  - user: alice@canonical.com
    access: add-model
- name: controller-36
  uuid: 00000000-0000-0000-0000-000000000036
  cloud: test-cloud
  region: test-region-1
  agent-version: "3.6.1"
  cloud-regions:
  - cloud: test-cloud
    region: test-region-1
    priority: 1
  users:
  - user: alice@canonical.com
    access: add-model
`[1:]

	// A fleet with only a 4.x controller.
	only40Env := `
clouds:
- name: test-cloud
  type: test-provider
  regions:
  - name: test-region-1
  users:
  - user: alice@canonical.com
    access: add-model
cloud-credentials:
- name: test-credential-1
  owner: alice@canonical.com
  cloud: test-cloud
  auth-type: empty
controllers:
- name: controller-40
  uuid: 00000000-0000-0000-0000-000000000040
  cloud: test-cloud
  region: test-region-1
  agent-version: "4.0.2"
  cloud-regions:
  - cloud: test-cloud
    region: test-region-1
    priority: 10
  users:
  - user: alice@canonical.com
    access: add-model
`[1:]

	const modelUUID = "00000001-0000-0000-0000-000000000001"
	createModelMock := createModel(`uuid: 00000001-0000-0000-0000-000000000001
status:
  status: started
  info: running a test
life: alive
users:
- user: alice@canonical.com
  access: admin
`)

	cloudCredTag := names.NewCloudCredentialTag("test-cloud/alice@canonical.com/test-credential-1")

	tests := []struct {
		name             string
		env              string
		maxMajor         int
		controllerName   string
		expectController string
		expectError      string
	}{{
		name:             "constrained client skips the higher-priority incompatible controller",
		env:              mixedFleetEnv,
		maxMajor:         3,
		expectController: "controller-36",
	}, {
		name:             "unconstrained client uses the higher-priority controller",
		env:              mixedFleetEnv,
		maxMajor:         0,
		expectController: "controller-40",
	}, {
		name:        "constrained client with no compatible controller fails",
		env:         only40Env,
		maxMajor:    3,
		expectError: "no controller compatible with your Juju client is available; please upgrade your client to use the available controllers",
	}, {
		name:           "constrained client naming a too-new controller fails",
		env:            mixedFleetEnv,
		maxMajor:       3,
		controllerName: "controller-40",
		expectError:    `controller "controller-40" \(version "4.0.2"\) is not compatible with your Juju client; please upgrade your client to use this controller`,
	}}

	for _, test := range tests {
		c.Run(test.name, func(c *qt.C) {
			ctx := context.Background()
			j := newTestJujuManager(c, &parameters{
				Dialer: &jimmtest.Dialer{
					API: &jimmtest.API{
						UpdateCloudsCredentialForce_: func(context.Context, jujuparams.TaggedCredential) ([]jujuparams.UpdateCredentialResult, error) {
							return []jujuparams.UpdateCredentialResult{{}}, nil
						},
						GrantJIMMModelAdmin_: func(context.Context, names.ModelTag) error {
							return nil
						},
						CreateModel_: createModelMock,
					},
				},
			})

			env := jimmtest.ParseEnvironment(c, test.env)
			env.PopulateDBAndPermissions(c, j.ResourceTag(), j.Database, j.OpenFGAClient)

			err := j.CredentialStore.Put(ctx, cloudCredTag, map[string]string{"key": "value"})
			c.Assert(err, qt.IsNil)

			dbUser := env.User("alice@canonical.com").DBObject(c, j.Database)
			user := openfga.NewUser(&dbUser, j.OpenFGAClient)
			user.JimmAdmin = true

			args := juju.ModelCreateArgs{
				Name:                      "test-model",
				Owner:                     names.NewUserTag("alice@canonical.com"),
				Cloud:                     names.NewCloudTag("test-cloud"),
				CloudRegion:               "test-region-1",
				CloudCredential:           cloudCredTag,
				ControllerName:            test.controllerName,
				MaxControllerMajorVersion: test.maxMajor,
			}

			_, err = j.AddModel(ctx, user, &args)
			if test.expectError != "" {
				c.Assert(err, qt.ErrorMatches, test.expectError)
				return
			}
			c.Assert(err, qt.IsNil)

			m := dbmodel.Model{UUID: sql.NullString{String: modelUUID, Valid: true}}
			err = j.Database.GetModel(ctx, &m)
			c.Assert(err, qt.IsNil)
			c.Check(m.Controller.Name, qt.Equals, test.expectController)
		})
	}
}
