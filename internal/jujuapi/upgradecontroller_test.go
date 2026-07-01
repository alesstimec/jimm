// Copyright 2026 Canonical.

package jujuapi_test

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/juju/version/v2"

	"github.com/canonical/jimm/v3/internal/errors"
	"github.com/canonical/jimm/v3/internal/jujuapi"
	"github.com/canonical/jimm/v3/internal/openfga"
	"github.com/canonical/jimm/v3/internal/testutils/jimmtest"
	"github.com/canonical/jimm/v3/internal/testutils/jimmtest/mocks"
	apiparams "github.com/canonical/jimm/v3/pkg/api/params"
)

func TestUpgradeController_Unauthorized(t *testing.T) {
	c := qt.New(t)

	ctx := c.Context()
	jimm := &jimmtest.JIMM{
		JujuManager_: func() jujuapi.JujuManager {
			return &mocks.JujuManager{}
		},
	}
	root := newTestControllerRoot(jimm, "alice@canonical.com", false)

	_, err := root.UpgradeController(ctx, apiparams.UpgradeControllerRequest{
		ControllerName: "test-controller",
	})
	c.Assert(errors.ErrorCode(err), qt.Equals, errors.CodeUnauthorized)
	c.Assert(err, qt.ErrorMatches, "unauthorized")
}

func TestUpgradeController_Success(t *testing.T) {
	c := qt.New(t)

	ctx := c.Context()
	targetVersion, err := version.Parse("3.6.12")
	c.Assert(err, qt.IsNil)
	chosenVersion, err := version.Parse("3.6.12")
	c.Assert(err, qt.IsNil)

	called := false
	jimm := &jimmtest.JIMM{
		JujuManager_: func() jujuapi.JujuManager {
			return &mocks.JujuManager{
				ModelManager: mocks.ModelManager{
					UpgradeController_: func(_ context.Context, _ *openfga.User, controllerName string, tv version.Number, stream string, ignoreAgentVersions bool, dryRun bool) (version.Number, error) {
						called = true
						c.Check(controllerName, qt.Equals, "test-controller")
						c.Check(tv, qt.DeepEquals, targetVersion)
						c.Check(stream, qt.Equals, "")
						c.Check(ignoreAgentVersions, qt.IsFalse)
						c.Check(dryRun, qt.IsFalse)
						return chosenVersion, nil
					},
				},
			}
		},
	}
	root := newTestControllerRoot(jimm, "alice@canonical.com", true)

	resp, err := root.UpgradeController(ctx, apiparams.UpgradeControllerRequest{
		ControllerName: "test-controller",
		TargetVersion:  targetVersion,
	})
	c.Assert(err, qt.IsNil)
	c.Assert(called, qt.IsTrue)
	c.Assert(resp.ChosenVersion, qt.DeepEquals, chosenVersion)
}

func TestUpgradeController_DryRun(t *testing.T) {
	c := qt.New(t)

	ctx := c.Context()
	chosenVersion, err := version.Parse("3.6.12")
	c.Assert(err, qt.IsNil)

	called := false
	jimm := &jimmtest.JIMM{
		JujuManager_: func() jujuapi.JujuManager {
			return &mocks.JujuManager{
				ModelManager: mocks.ModelManager{
					UpgradeController_: func(_ context.Context, _ *openfga.User, _ string, _ version.Number, _ string, _ bool, dryRun bool) (version.Number, error) {
						called = true
						c.Check(dryRun, qt.IsTrue)
						return chosenVersion, nil
					},
				},
			}
		},
	}
	root := newTestControllerRoot(jimm, "alice@canonical.com", true)

	resp, err := root.UpgradeController(ctx, apiparams.UpgradeControllerRequest{
		ControllerName: "test-controller",
		DryRun:         true,
	})
	c.Assert(err, qt.IsNil)
	c.Assert(called, qt.IsTrue)
	c.Assert(resp.ChosenVersion, qt.DeepEquals, chosenVersion)
}

func TestUpgradeController_ControllerNotFound(t *testing.T) {
	c := qt.New(t)

	ctx := c.Context()
	jimm := &jimmtest.JIMM{
		JujuManager_: func() jujuapi.JujuManager {
			return &mocks.JujuManager{
				ModelManager: mocks.ModelManager{
					UpgradeController_: func(_ context.Context, _ *openfga.User, _ string, _ version.Number, _ string, _ bool, _ bool) (version.Number, error) {
						return version.Zero, errors.Codef(errors.CodeNotFound, "controller not found")
					},
				},
			}
		},
	}
	root := newTestControllerRoot(jimm, "alice@canonical.com", true)

	_, err := root.UpgradeController(ctx, apiparams.UpgradeControllerRequest{
		ControllerName: "nonexistent",
	})
	c.Assert(errors.ErrorCode(err), qt.Equals, errors.CodeNotFound)
}

func TestUpgradeController_AllOptions(t *testing.T) {
	c := qt.New(t)

	ctx := c.Context()
	chosenVersion, err := version.Parse("3.6.9")
	c.Assert(err, qt.IsNil)

	called := false
	jimm := &jimmtest.JIMM{
		JujuManager_: func() jujuapi.JujuManager {
			return &mocks.JujuManager{
				ModelManager: mocks.ModelManager{
					UpgradeController_: func(_ context.Context, _ *openfga.User, controllerName string, _ version.Number, stream string, ignoreAgentVersions bool, dryRun bool) (version.Number, error) {
						called = true
						c.Check(controllerName, qt.Equals, "test-controller")
						c.Check(stream, qt.Equals, "proposed")
						c.Check(ignoreAgentVersions, qt.IsTrue)
						c.Check(dryRun, qt.IsTrue)
						return chosenVersion, nil
					},
				},
			}
		},
	}
	root := newTestControllerRoot(jimm, "alice@canonical.com", true)

	resp, err := root.UpgradeController(ctx, apiparams.UpgradeControllerRequest{
		ControllerName:      "test-controller",
		AgentStream:         "proposed",
		IgnoreAgentVersions: true,
		DryRun:              true,
	})
	c.Assert(err, qt.IsNil)
	c.Assert(called, qt.IsTrue)
	c.Assert(resp.ChosenVersion, qt.DeepEquals, chosenVersion)
}
