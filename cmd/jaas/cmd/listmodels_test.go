// Copyright 2026 Canonical.

package cmd

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	"gopkg.in/yaml.v2"

	"github.com/canonical/jimm/v3/pkg/api/params"
)

func assertListModelsTabularOutput(c *qt.C, out string, rows []params.ModelControllerInfoListItem) {
	var b strings.Builder
	b.WriteString("^Model name\\s+Model UUID\\s+Controller name\\s+Controller UUID\\s+Upgrade to status\\n")
	for _, row := range rows {
		b.WriteString(regexp.QuoteMeta(row.ModelName))
		b.WriteString("\\s+")
		b.WriteString(regexp.QuoteMeta(row.ModelUUID))
		b.WriteString("\\s+")
		b.WriteString(regexp.QuoteMeta(row.ControllerName))
		b.WriteString("\\s+")
		b.WriteString(regexp.QuoteMeta(row.ControllerUUID))
		b.WriteString("\\s+")
		b.WriteString(regexp.QuoteMeta(row.UpgradeToJobStatus))
		b.WriteString("\\n")
	}
	b.WriteString("$")

	c.Assert(out, qt.Matches, b.String())
}

func TestListModels(t *testing.T) {
	c := qt.New(t)
	cmdMocks := setupCmdMocks(c)

	expectedModels := []params.ModelControllerInfoListItem{
		{
			ModelName:          "model-1",
			ModelUUID:          "12345678-1234-1234-1234-123456789abc",
			ControllerName:     "controller-1",
			ControllerUUID:     "87654321-4321-4321-4321-cba987654321",
			UpgradeToJobStatus: "upgrade-to in progress",
		},
		{
			ModelName:      "model-2",
			ModelUUID:      "22345678-1234-1234-1234-123456789abc",
			ControllerName: "controller-2",
			ControllerUUID: "97654321-4321-4321-4321-cba987654321",
		},
	}

	cmdMocks.client.EXPECT().ListModels().Return(expectedModels, nil)
	cmdMocks.client.EXPECT().Close().Return(nil)

	command := &listModelsCommand{}
	command.setJIMMAPI(cmdMocks.client)
	command.SetClientStore(cmdMocks.store)

	initCommand(c, command)

	ctx := newTestContext(c)

	err := command.Run(ctx)
	c.Assert(err, qt.IsNil)

	output := ctx.Stdout.(*bytes.Buffer).String()
	var actual []params.ModelControllerInfoListItem
	err = yaml.Unmarshal([]byte(output), &actual)
	c.Assert(err, qt.IsNil)
	c.Assert(actual, qt.DeepEquals, expectedModels)
}

func TestListModelsEmpty(t *testing.T) {
	c := qt.New(t)
	cmdMocks := setupCmdMocks(c)

	cmdMocks.client.EXPECT().ListModels().Return([]params.ModelControllerInfoListItem{}, nil)
	cmdMocks.client.EXPECT().Close().Return(nil)

	command := &listModelsCommand{}
	command.setJIMMAPI(cmdMocks.client)
	command.SetClientStore(cmdMocks.store)

	initCommand(c, command)

	ctx := newTestContext(c)

	err := command.Run(ctx)
	c.Assert(err, qt.IsNil)

	output := ctx.Stdout.(*bytes.Buffer).String()
	var actual []params.ModelControllerInfoListItem
	err = yaml.Unmarshal([]byte(output), &actual)
	c.Assert(err, qt.IsNil)
	c.Assert(actual, qt.DeepEquals, []params.ModelControllerInfoListItem{})
}

func TestListModelsTabular(t *testing.T) {
	c := qt.New(t)
	cmdMocks := setupCmdMocks(c)

	expectedModels := []params.ModelControllerInfoListItem{
		{
			ModelName:          "model-1",
			ModelUUID:          "12345678-1234-1234-1234-123456789abc",
			ControllerName:     "controller-1",
			ControllerUUID:     "87654321-4321-4321-4321-cba987654321",
			UpgradeToJobStatus: "upgrade-to in progress",
		},
		{
			ModelName:      "model-2",
			ModelUUID:      "22345678-1234-1234-1234-123456789abc",
			ControllerName: "controller-2",
			ControllerUUID: "97654321-4321-4321-4321-cba987654321",
		},
	}

	cmdMocks.client.EXPECT().ListModels().Return(expectedModels, nil)
	cmdMocks.client.EXPECT().Close().Return(nil)

	command := &listModelsCommand{}
	command.setJIMMAPI(cmdMocks.client)
	command.SetClientStore(cmdMocks.store)

	initCommand(c, command, "--format", "tabular")

	ctx := newTestContext(c)

	err := command.Run(ctx)
	c.Assert(err, qt.IsNil)

	assertListModelsTabularOutput(c, ctx.Stdout.(*bytes.Buffer).String(), expectedModels)
}
