// Copyright 2025 Canonical.

package cmd

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	jujuparams "github.com/juju/juju/rpc/params"
	"go.uber.org/mock/gomock"

	apiparams "github.com/canonical/jimm/v3/pkg/api/params"
)

type expectedUpgradeToRow struct {
	modelUUID string
	status    string
	errorText string
}

func assertUpgradeToTabularOutput(c *qt.C, out string, rows []expectedUpgradeToRow) {
	var b strings.Builder
	b.WriteString("^Model UUID\\s+Status\\s+Error\\n")
	for _, row := range rows {
		b.WriteString(regexp.QuoteMeta(row.modelUUID))
		b.WriteString("\\s+")
		b.WriteString(regexp.QuoteMeta(row.status))
		b.WriteString("\\s+")
		b.WriteString(regexp.QuoteMeta(row.errorText))
		b.WriteString("\\n")
	}
	b.WriteString("$")

	c.Assert(out, qt.Matches, b.String())
}

func TestUpgradeTo(t *testing.T) {
	c := qt.New(t)
	s := setupCmdMocks(c)

	testModelUUID := "93608db4-f1cb-4da5-9926-8233981aef0a"
	testTargetController := "test-controller"

	upgradeToParams := &apiparams.UpgradeToRequest{
		TargetControllerName: testTargetController,
		ModelUUIDs:           []string{testModelUUID},
	}

	s.client.EXPECT().UpgradeTo(gomock.Any(), upgradeToParams).Return(apiparams.UpgradeToResponse{
		Results: []apiparams.UpgradeToResult{{}},
	}, nil)
	s.client.EXPECT().Close().Return(nil)

	upgradeToCmd := &upgradeToCommand{}
	upgradeToCmd.setJIMMAPI(s.client)
	upgradeToCmd.SetClientStore(s.store)
	initCommand(c, upgradeToCmd, testTargetController, testModelUUID)

	ctx := newTestContext(c)
	err := upgradeToCmd.Run(ctx)
	c.Assert(err, qt.IsNil)
	out := ctx.Stdout.(*bytes.Buffer).String()
	assertUpgradeToTabularOutput(c, out, []expectedUpgradeToRow{{
		modelUUID: testModelUUID,
		status:    "success",
		errorText: "",
	}})
}

func TestUpgradeToWithFailureResponse(t *testing.T) {
	c := qt.New(t)
	s := setupCmdMocks(c)

	testModelUUID := "93608db4-f1cb-4da5-9926-8233981aef0a"
	testTargetController := "test-controller"
	testErrorMessage := "upgrade failed: controller not ready"

	upgradeToParams := &apiparams.UpgradeToRequest{
		TargetControllerName: testTargetController,
		ModelUUIDs:           []string{testModelUUID},
	}

	// Now the error is returned directly by UpgradeTo instead of embedded in the response.
	s.client.EXPECT().UpgradeTo(gomock.Any(), upgradeToParams).Return(apiparams.UpgradeToResponse{}, errors.New(testErrorMessage))
	s.client.EXPECT().Close().Return(nil)

	upgradeToCmd := &upgradeToCommand{}
	upgradeToCmd.setJIMMAPI(s.client)
	initCommand(c, upgradeToCmd, testTargetController, testModelUUID)

	ctx := newTestContext(c)
	err := upgradeToCmd.Run(ctx)
	c.Assert(err, qt.ErrorMatches, ".*upgrade-to request failed: .*"+testErrorMessage+".*")
	c.Assert(ctx.Stdout.(*bytes.Buffer).String(), qt.Equals, "")
}

func TestUpgradeToWithError(t *testing.T) {
	c := qt.New(t)
	s := setupCmdMocks(c)

	testModelUUID := "93608db4-f1cb-4da5-9926-8233981aef0a"
	testTargetController := "test-controller"

	upgradeToParams := &apiparams.UpgradeToRequest{
		TargetControllerName: testTargetController,
		ModelUUIDs:           []string{testModelUUID},
	}
	errorToReturn := errors.New("failed to initiate upgrade")
	s.client.EXPECT().UpgradeTo(gomock.Any(), upgradeToParams).Return(apiparams.UpgradeToResponse{}, errorToReturn)
	s.client.EXPECT().Close().Return(nil)

	upgradeToCmd := &upgradeToCommand{}
	upgradeToCmd.setJIMMAPI(s.client)
	initCommand(c, upgradeToCmd, testTargetController, testModelUUID)

	ctx := newTestContext(c)
	err := upgradeToCmd.Run(ctx)
	c.Assert(err, qt.ErrorMatches, ".*failed to initiate upgrade.*")
	c.Assert(ctx.Stdout.(*bytes.Buffer).String(), qt.Equals, "")
}

func TestUpgradeToFailsWithMissingArgs(t *testing.T) {
	c := qt.New(t)
	upgradeToCmd := &upgradeToCommand{}
	err := initCommandWithError(upgradeToCmd)
	c.Assert(err, qt.ErrorMatches, "missing required arguments: controller name and at least one model UUID")
}

func TestUpgradeToFailsWithOnlyOneArg(t *testing.T) {
	c := qt.New(t)
	upgradeToCmd := &upgradeToCommand{}
	err := initCommandWithError(upgradeToCmd, "3.5.0")
	c.Assert(err, qt.ErrorMatches, "missing required arguments: controller name and at least one model UUID")
}

func TestUpgradeToFailsWithInvalidModelUUID(t *testing.T) {
	c := qt.New(t)
	upgradeToCmd := &upgradeToCommand{}
	err := initCommandWithError(upgradeToCmd, "3.5.0", "invalid-uuid")
	c.Assert(err, qt.ErrorMatches, "invalid model UUID: invalid-uuid")
}

func TestUpgradeToWithPositionalArgs(t *testing.T) {
	c := qt.New(t)
	s := setupCmdMocks(c)

	testModelUUID := "93608db4-f1cb-4da5-9926-8233981aef0a"
	testTargetController := "test-controller"

	upgradeToParams := &apiparams.UpgradeToRequest{
		TargetControllerName: testTargetController,
		ModelUUIDs:           []string{testModelUUID},
	}

	s.client.EXPECT().UpgradeTo(gomock.Any(), upgradeToParams).Return(apiparams.UpgradeToResponse{
		Results: []apiparams.UpgradeToResult{{}},
	}, nil)
	s.client.EXPECT().Close().Return(nil)

	upgradeToCmd := &upgradeToCommand{}
	upgradeToCmd.setJIMMAPI(s.client)
	upgradeToCmd.SetClientStore(s.store)
	initCommand(c, upgradeToCmd, testTargetController, testModelUUID)

	ctx := newTestContext(c)
	err := upgradeToCmd.Run(ctx)
	c.Assert(err, qt.IsNil)
	out := ctx.Stdout.(*bytes.Buffer).String()
	assertUpgradeToTabularOutput(c, out, []expectedUpgradeToRow{{
		modelUUID: testModelUUID,
		status:    "success",
		errorText: "",
	}})
}

func TestUpgradeToWithPerModelFailureInResponse(t *testing.T) {
	c := qt.New(t)
	s := setupCmdMocks(c)

	modelUUID1 := "93608db4-f1cb-4da5-9926-8233981aef0a"
	modelUUID2 := "2cb433a6-04eb-4ec4-9567-90426d20a004"
	testTargetController := "test-controller"
	failureMsg := "failed to run upgrade"

	upgradeToParams := &apiparams.UpgradeToRequest{
		TargetControllerName: testTargetController,
		ModelUUIDs:           []string{modelUUID1, modelUUID2},
	}

	s.client.EXPECT().UpgradeTo(gomock.Any(), upgradeToParams).Return(apiparams.UpgradeToResponse{
		Results: []apiparams.UpgradeToResult{
			{},
			{Error: &jujuparams.Error{Message: failureMsg}},
		},
	}, nil)
	s.client.EXPECT().Close().Return(nil)

	upgradeToCmd := &upgradeToCommand{}
	upgradeToCmd.setJIMMAPI(s.client)
	upgradeToCmd.SetClientStore(s.store)
	initCommand(c, upgradeToCmd, testTargetController, modelUUID1, modelUUID2)

	ctx := newTestContext(c)
	err := upgradeToCmd.Run(ctx)
	c.Assert(err, qt.IsNil)
	out := ctx.Stdout.(*bytes.Buffer).String()
	assertUpgradeToTabularOutput(c, out, []expectedUpgradeToRow{
		{modelUUID: modelUUID1, status: "success", errorText: ""},
		{modelUUID: modelUUID2, status: "failed", errorText: failureMsg},
	})
}

func TestUpgradeToFailsWhenResponseLengthDoesNotMatchModelUUIDs(t *testing.T) {
	c := qt.New(t)
	s := setupCmdMocks(c)

	modelUUID1 := "93608db4-f1cb-4da5-9926-8233981aef0a"
	modelUUID2 := "2cb433a6-04eb-4ec4-9567-90426d20a004"
	testTargetController := "test-controller"

	upgradeToParams := &apiparams.UpgradeToRequest{
		TargetControllerName: testTargetController,
		ModelUUIDs:           []string{modelUUID1, modelUUID2},
	}

	s.client.EXPECT().UpgradeTo(gomock.Any(), upgradeToParams).Return(apiparams.UpgradeToResponse{
		Results: []apiparams.UpgradeToResult{{}},
	}, nil)
	s.client.EXPECT().Close().Return(nil)

	upgradeToCmd := &upgradeToCommand{}
	upgradeToCmd.setJIMMAPI(s.client)
	upgradeToCmd.SetClientStore(s.store)
	initCommand(c, upgradeToCmd, testTargetController, modelUUID1, modelUUID2)

	ctx := newTestContext(c)
	err := upgradeToCmd.Run(ctx)
	c.Assert(err, qt.ErrorMatches, "invalid upgrade-to response: got 1 results for 2 model UUIDs")
	c.Assert(ctx.Stdout.(*bytes.Buffer).String(), qt.Equals, "")
}
