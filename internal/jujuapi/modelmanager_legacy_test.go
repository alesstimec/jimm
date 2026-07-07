// Copyright 2026 Canonical.

package jujuapi_test

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/juju/juju/api/base"
	"github.com/juju/juju/core/model"
	jujuparams "github.com/juju/juju/rpc/params"
	"github.com/juju/names/v6"

	"github.com/canonical/jimm/v3/internal/jimm/juju"
	"github.com/canonical/jimm/v3/internal/jimmhttp"
	"github.com/canonical/jimm/v3/internal/jujuapi"
	"github.com/canonical/jimm/v3/internal/jujuclient"
	"github.com/canonical/jimm/v3/internal/openfga"
	"github.com/canonical/jimm/v3/internal/testutils/jimmtest"
	"github.com/canonical/jimm/v3/internal/testutils/jimmtest/mocks"
)

const testModelUUID = "00000000-0000-0000-0000-000000000001"

// TestModelManagerAdvertisesLegacyAndCurrent asserts the ModelManager facade
// advertises both the 3.6 (v10) and 4.x (v11) versions.
func TestModelManagerAdvertisesLegacyAndCurrent(t *testing.T) {
	c := qt.New(t)
	c.Assert(jujuapi.SupportedFacades()["ModelManager"], qt.DeepEquals, []int{10, 11})
}

// TestCreateModelLegacy checks that the v10 CreateModel handler accepts an
// owner-tag request and returns an owner-tag response, reusing the v11 logic.
func TestCreateModelLegacy(t *testing.T) {
	c := qt.New(t)

	jujuManager := mocks.JujuManager{
		ModelManager: mocks.ModelManager{
			AddModel_: func(ctx context.Context, u *openfga.User, args *juju.ModelCreateArgs) (base.ModelInfo, error) {
				// The owner tag must have been converted to a qualifier.
				c.Check(args.Owner.Id(), qt.Equals, "alice@external")
				return base.ModelInfo{
					Name:            args.Name,
					UUID:            testModelUUID,
					Qualifier:       model.Qualifier("alice@external"),
					Type:            model.IAAS,
					Cloud:           "aws",
					CloudRegion:     "eu-west-1",
					CloudCredential: "aws/alice@external/cred",
				}, nil
			},
		},
	}
	cr := newTestControllerRoot(jujuJIMM(&jujuManager), "alice@external", true)

	got, err := cr.CreateModelLegacy(context.Background(), jujuparams.ModelCreateArgsLegacy{
		Name:     "mymodel",
		OwnerTag: "user-alice@external",
	})
	c.Assert(err, qt.IsNil)
	c.Check(got.OwnerTag, qt.Equals, "user-alice@external")
	c.Check(got.Name, qt.Equals, "mymodel")
	c.Check(got.UUID, qt.Equals, testModelUUID)
}

// TestCreateModelClientVersionPlacementCap verifies that both CreateModel
// handlers derive the controller-version placement cap from the client version
// reported on the connection, per the JIMM/Juju interoperability spec: the cap
// is the reported major version, and a client that reports no (or an
// unparseable) version is treated as a Juju 3.6 client, whichever facade
// version it negotiated.
func TestCreateModelClientVersionPlacementCap(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		about         string
		clientVersion string
		useLegacy     bool
		expectedCap   int
	}{{
		about:       "no reported version, v11 handler",
		expectedCap: 3,
	}, {
		about:       "no reported version, v10 handler",
		useLegacy:   true,
		expectedCap: 3,
	}, {
		about:         "4.x client, v11 handler",
		clientVersion: "4.0.2",
		expectedCap:   4,
	}, {
		about:         "4.x client, v10 handler",
		clientVersion: "4.0.2",
		useLegacy:     true,
		expectedCap:   4,
	}, {
		about:         "3.6 client, v11 handler",
		clientVersion: "3.6.8",
		expectedCap:   3,
	}, {
		about:         "unparseable reported version, v11 handler",
		clientVersion: "not-a-version",
		expectedCap:   3,
	}}

	for _, test := range tests {
		c.Run(test.about, func(c *qt.C) {
			gotCap := -1
			jujuManager := mocks.JujuManager{
				ModelManager: mocks.ModelManager{
					AddModel_: func(ctx context.Context, u *openfga.User, args *juju.ModelCreateArgs) (base.ModelInfo, error) {
						gotCap = args.MaxControllerMajorVersion
						return base.ModelInfo{
							Name:            args.Name,
							UUID:            testModelUUID,
							Qualifier:       model.Qualifier("alice@external"),
							Type:            model.IAAS,
							Cloud:           "aws",
							CloudRegion:     "eu-west-1",
							CloudCredential: "aws/alice@external/cred",
						}, nil
					},
				},
			}
			cr := newTestControllerRoot(jujuJIMM(&jujuManager), "alice@external", true)

			ctx := context.Background()
			if test.clientVersion != "" {
				ctx = jimmhttp.ContextWithClientVersion(ctx, test.clientVersion)
			}
			var err error
			if test.useLegacy {
				_, err = cr.CreateModelLegacy(ctx, jujuparams.ModelCreateArgsLegacy{
					Name:     "mymodel",
					OwnerTag: "user-alice@external",
				})
			} else {
				_, err = cr.CreateModel(ctx, jujuparams.ModelCreateArgs{
					Name:      "mymodel",
					Qualifier: "alice@external",
				})
			}
			c.Assert(err, qt.IsNil)
			c.Check(gotCap, qt.Equals, test.expectedCap)
		})
	}
}

// TestListModelsLegacy checks the v10 ListModels handler returns owner tags.
func TestListModelsLegacy(t *testing.T) {
	c := qt.New(t)

	jujuManager := mocks.JujuManager{
		ListModels_: func(ctx context.Context, user *openfga.User) ([]base.UserModel, error) {
			return []base.UserModel{{
				Name:      "mymodel",
				UUID:      testModelUUID,
				Qualifier: model.Qualifier("alice@external"),
				Type:      model.IAAS,
			}}, nil
		},
	}
	cr := newTestControllerRoot(jujuJIMM(&jujuManager), "alice@external", true)

	got, err := cr.ListModelsLegacy(context.Background(), jujuparams.Entity{})
	c.Assert(err, qt.IsNil)
	c.Assert(got.UserModels, qt.HasLen, 1)
	c.Check(got.UserModels[0].OwnerTag, qt.Equals, "user-alice@external")
	c.Check(got.UserModels[0].Name, qt.Equals, "mymodel")
	c.Check(got.UserModels[0].UUID, qt.Equals, testModelUUID)
}

// TestModelInfoLegacy checks the v10 ModelInfo handler returns owner tags.
func TestModelInfoLegacy(t *testing.T) {
	c := qt.New(t)

	mt := names.NewModelTag(testModelUUID)
	jujuManager := mocks.JujuManager{
		ModelManager: mocks.ModelManager{
			ModelInfo_: func(ctx context.Context, u *openfga.User, gotTag names.ModelTag) (jujuclient.ModelInfo, error) {
				c.Check(gotTag.String(), qt.Equals, mt.String())
				return jujuclient.ModelInfo{ModelInfo: base.ModelInfo{
					Name:            "mymodel",
					UUID:            testModelUUID,
					Qualifier:       model.Qualifier("alice@external"),
					Type:            model.IAAS,
					Cloud:           "aws",
					CloudRegion:     "eu-west-1",
					CloudCredential: "aws/alice@external/cred",
				}}, nil
			},
		},
	}
	cr := newTestControllerRoot(jujuJIMM(&jujuManager), "alice@external", true)

	got, err := cr.ModelInfoLegacy(context.Background(), jujuparams.Entities{
		Entities: []jujuparams.Entity{{Tag: mt.String()}},
	})
	c.Assert(err, qt.IsNil)
	c.Assert(got.Results, qt.HasLen, 1)
	c.Assert(got.Results[0].Result, qt.IsNotNil)
	c.Check(got.Results[0].Result.OwnerTag, qt.Equals, "user-alice@external")
	c.Check(got.Results[0].Result.Name, qt.Equals, "mymodel")
}

// jujuJIMM wraps a JujuManager mock in a jimmtest.JIMM.
func jujuJIMM(jm *mocks.JujuManager) *jimmtest.JIMM {
	return &jimmtest.JIMM{
		JujuManager_: func() jujuapi.JujuManager {
			return jm
		},
	}
}
