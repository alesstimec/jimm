// Copyright 2026 Canonical.

package cmd

import (
	"bytes"
	"errors"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/juju/version/v2"

	apiparams "github.com/canonical/jimm/v3/pkg/api/params"
)

func TestUpgradeController_Success(t *testing.T) {
	c := qt.New(t)
	s := setupCmdMocks(c)

	chosenVersion, err := version.Parse("3.6.12")
	c.Assert(err, qt.IsNil)

	req := &apiparams.UpgradeControllerRequest{
		ControllerName: "my-controller",
	}
	s.client.EXPECT().UpgradeController(req).Return(apiparams.UpgradeControllerResponse{
		ChosenVersion: chosenVersion,
	}, nil)
	s.client.EXPECT().Close().Return(nil)

	upgradeCmd := &upgradeControllerCommand{}
	upgradeCmd.setJIMMAPI(s.client)
	upgradeCmd.SetClientStore(s.store)
	initCommand(c, upgradeCmd, "my-controller")

	ctx := newTestContext(c)
	err = upgradeCmd.Run(ctx)
	c.Assert(err, qt.IsNil)
	c.Assert(ctx.Stdout.(*bytes.Buffer).String(), qt.Equals, "started upgrade to 3.6.12\n")
	c.Assert(ctx.Stderr.(*bytes.Buffer).String(), qt.Equals, "")
}

func TestUpgradeController_WithTargetVersion(t *testing.T) {
	c := qt.New(t)
	s := setupCmdMocks(c)

	targetVersion, err := version.Parse("3.6.8")
	c.Assert(err, qt.IsNil)

	req := &apiparams.UpgradeControllerRequest{
		ControllerName: "my-controller",
		TargetVersion:  targetVersion,
	}
	s.client.EXPECT().UpgradeController(req).Return(apiparams.UpgradeControllerResponse{
		ChosenVersion: targetVersion,
	}, nil)
	s.client.EXPECT().Close().Return(nil)

	upgradeCmd := &upgradeControllerCommand{}
	upgradeCmd.setJIMMAPI(s.client)
	upgradeCmd.SetClientStore(s.store)
	initCommand(c, upgradeCmd, "my-controller", "--target-version", "3.6.8")

	ctx := newTestContext(c)
	err = upgradeCmd.Run(ctx)
	c.Assert(err, qt.IsNil)
	c.Assert(ctx.Stdout.(*bytes.Buffer).String(), qt.Equals, "started upgrade to 3.6.8\n")
}

func TestUpgradeController_DryRun(t *testing.T) {
	c := qt.New(t)
	s := setupCmdMocks(c)

	chosenVersion, err := version.Parse("3.6.12")
	c.Assert(err, qt.IsNil)

	req := &apiparams.UpgradeControllerRequest{
		ControllerName: "my-controller",
		DryRun:         true,
	}
	s.client.EXPECT().UpgradeController(req).Return(apiparams.UpgradeControllerResponse{
		ChosenVersion: chosenVersion,
	}, nil)
	s.client.EXPECT().Close().Return(nil)

	upgradeCmd := &upgradeControllerCommand{}
	upgradeCmd.setJIMMAPI(s.client)
	upgradeCmd.SetClientStore(s.store)
	initCommand(c, upgradeCmd, "my-controller", "--dry-run")

	ctx := newTestContext(c)
	err = upgradeCmd.Run(ctx)
	c.Assert(err, qt.IsNil)
	c.Assert(ctx.Stdout.(*bytes.Buffer).String(), qt.Equals, "")
	// dry-run output goes to Stderr via ctxt.Infof
	c.Assert(ctx.Stderr.(*bytes.Buffer).String(), qt.Contains, "3.6.12")
	c.Assert(ctx.Stderr.(*bytes.Buffer).String(), qt.Contains, "no changes applied")
}

func TestUpgradeController_AllFlags(t *testing.T) {
	c := qt.New(t)
	s := setupCmdMocks(c)

	targetVersion, err := version.Parse("3.6.5")
	c.Assert(err, qt.IsNil)
	chosenVersion, err := version.Parse("3.6.5")
	c.Assert(err, qt.IsNil)

	req := &apiparams.UpgradeControllerRequest{
		ControllerName:      "my-controller",
		TargetVersion:       targetVersion,
		AgentStream:         "proposed",
		IgnoreAgentVersions: true,
		DryRun:              true,
	}
	s.client.EXPECT().UpgradeController(req).Return(apiparams.UpgradeControllerResponse{
		ChosenVersion: chosenVersion,
	}, nil)
	s.client.EXPECT().Close().Return(nil)

	upgradeCmd := &upgradeControllerCommand{}
	upgradeCmd.setJIMMAPI(s.client)
	upgradeCmd.SetClientStore(s.store)
	initCommand(c, upgradeCmd,
		"my-controller",
		"--target-version", "3.6.5",
		"--agent-stream", "proposed",
		"--ignore-agent-versions",
		"--dry-run",
	)

	ctx := newTestContext(c)
	err = upgradeCmd.Run(ctx)
	c.Assert(err, qt.IsNil)
}

func TestUpgradeController_APIError(t *testing.T) {
	c := qt.New(t)
	s := setupCmdMocks(c)

	req := &apiparams.UpgradeControllerRequest{
		ControllerName: "my-controller",
	}
	s.client.EXPECT().UpgradeController(req).Return(apiparams.UpgradeControllerResponse{}, errors.New("controller not found"))
	s.client.EXPECT().Close().Return(nil)

	upgradeCmd := &upgradeControllerCommand{}
	upgradeCmd.setJIMMAPI(s.client)
	upgradeCmd.SetClientStore(s.store)
	initCommand(c, upgradeCmd, "my-controller")

	ctx := newTestContext(c)
	err := upgradeCmd.Run(ctx)
	c.Assert(err, qt.ErrorMatches, "upgrade-controller failed: controller not found")
	c.Assert(ctx.Stdout.(*bytes.Buffer).String(), qt.Equals, "")
}

func TestUpgradeController_MissingControllerName(t *testing.T) {
	c := qt.New(t)

	upgradeCmd := &upgradeControllerCommand{}
	err := initCommandWithError(upgradeCmd)
	c.Assert(err, qt.ErrorMatches, "controller name is required")
}

func TestUpgradeController_InvalidTargetVersion(t *testing.T) {
	c := qt.New(t)

	upgradeCmd := &upgradeControllerCommand{}
	err := initCommandWithError(upgradeCmd, "my-controller", "--target-version", "not-a-version")
	c.Assert(err, qt.ErrorMatches, `invalid --target-version "not-a-version":.*`)
}

func TestUpgradeController_TooManyArgs(t *testing.T) {
	c := qt.New(t)

	upgradeCmd := &upgradeControllerCommand{}
	err := initCommandWithError(upgradeCmd, "my-controller", "extra-arg")
	c.Assert(err, qt.ErrorMatches, `unrecognized args:.*extra-arg.*`)
}
