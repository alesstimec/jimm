// Copyright 2026 Canonical.

package jujuapi_test

import (
	"context"
	"database/sql"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/canonical/jimm/v3/internal/dbmodel"
	"github.com/canonical/jimm/v3/internal/jujuapi"
	"github.com/canonical/jimm/v3/internal/openfga"
	"github.com/canonical/jimm/v3/internal/testutils/jimmtest/mocks"
)

// TestControllerAdvertisesLegacyAndCurrent asserts the Controller facade
// advertises the 3.6 (v12) and 4.x (v14, v15) versions.
func TestControllerAdvertisesLegacyAndCurrent(t *testing.T) {
	c := qt.New(t)
	c.Assert(jujuapi.SupportedFacades()["Controller"], qt.DeepEquals, []int{12, 14, 15})
}

// TestAllModelsLegacy checks the Controller v12 AllModels handler reports
// models in owner-tag form.
func TestAllModelsLegacy(t *testing.T) {
	c := qt.New(t)

	jujuManager := mocks.JujuManager{
		ModelManager: mocks.ModelManager{
			ForEachUserModel_: func(ctx context.Context, u *openfga.User, f func(*dbmodel.Model, string) error) error {
				m := &dbmodel.Model{
					Name:              "mymodel",
					OwnerIdentityName: "alice@external",
				}
				m.UUID = sql.NullString{String: testModelUUID, Valid: true}
				return f(m, "admin")
			},
		},
	}
	cr := newTestControllerRoot(jujuJIMM(&jujuManager), "alice@external", true)

	got, err := cr.AllModelsLegacy(context.Background())
	c.Assert(err, qt.IsNil)
	c.Assert(got.UserModels, qt.HasLen, 1)
	c.Check(got.UserModels[0].OwnerTag, qt.Equals, "user-alice@external")
	c.Check(got.UserModels[0].Name, qt.Equals, "mymodel")
	c.Check(got.UserModels[0].UUID, qt.Equals, testModelUUID)
}
