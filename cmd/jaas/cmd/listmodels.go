// Copyright 2026 Canonical.

package cmd

import (
	"fmt"
	"io"

	"github.com/juju/cmd/v3"
	"github.com/juju/gnuflag"
	jujucmd "github.com/juju/juju/cmd"
	"github.com/juju/juju/cmd/modelcmd"
	"github.com/juju/juju/cmd/output"
	"github.com/juju/juju/jujuclient"

	apiparams "github.com/canonical/jimm/v3/pkg/api/params"
)

const (
	listModelsCommandDoc = `
Displays model and controller information for all models accessible to the authenticated user.
`
	listModelsCommandExample = `
    juju models
    juju models --format json
`
)

// NewListModelsCommand returns a command to list model controller information.
func NewListModelsCommand() cmd.Command {
	cmd := &listModelsCommand{}
	cmd.SetClientStore(jujuclient.NewFileClientStore())

	return modelcmd.WrapBase(cmd)
}

// listModelsCommand shows model and controller information for all models the user
// can access.
type listModelsCommand struct {
	jaasCommandBase
	out cmd.Output
}

// Info implements Command.Info.
func (c *listModelsCommand) Info() *cmd.Info {
	return jujucmd.Info(&cmd.Info{
		Name:     "models",
		Purpose:  "Lists all models accessible via JIMM.",
		Doc:      listModelsCommandDoc,
		Examples: listModelsCommandExample,
		Aliases:  []string{"list-models"},
	})
}

// SetFlags implements Command.SetFlags.
func (c *listModelsCommand) SetFlags(f *gnuflag.FlagSet) {
	c.CommandBase.SetFlags(f)
	c.out.AddFlags(f, "yaml", map[string]cmd.Formatter{
		"yaml":    cmd.FormatYaml,
		"json":    cmd.FormatJson,
		"tabular": c.formatTabular,
	})
}

// Run implements Command.Run.
func (c *listModelsCommand) Run(ctxt *cmd.Context) error {
	client, err := c.getJIMMAPI()
	if err != nil {
		return err
	}
	defer client.Close()

	models, err := client.ListModels()
	if err != nil {
		return err
	}

	if err := c.out.Write(ctxt, models); err != nil {
		return err
	}
	return nil
}

func (c *listModelsCommand) formatTabular(writer io.Writer, value any) error {
	models, ok := value.([]apiparams.ModelControllerInfoListItem)
	if !ok {
		return fmt.Errorf("expected []apiparams.ModelControllerInfoListItem, got %T", value)
	}

	tw := output.TabWriter(writer)
	w := output.Wrapper{TabWriter: tw}

	w.PrintHeaders(output.EmphasisHighlight.DefaultBold, "Model name", "Model UUID", "Controller name", "Controller UUID", "Upgrade to status")
	for _, model := range models {
		w.Println(model.ModelName, model.ModelUUID, model.ControllerName, model.ControllerUUID, model.UpgradeToJobStatus)
	}
	w.Flush()

	return nil
}
