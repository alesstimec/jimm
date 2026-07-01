// Copyright 2026 Canonical.

package cmd

import (
	"fmt"

	"github.com/juju/cmd/v3"
	"github.com/juju/gnuflag"
	jujucmd "github.com/juju/juju/cmd"
	"github.com/juju/juju/cmd/modelcmd"
	"github.com/juju/juju/jujuclient"
	"github.com/juju/version/v2"

	apiparams "github.com/canonical/jimm/v3/pkg/api/params"
)

const (
	upgradeControllerDoc = `
Upgrades the Juju agent running on the named backing controller to the next
available patch release. If --target-version is specified, upgrades to that
exact version instead.

The command requires the caller to be a JIMM admin.
`
	upgradeControllerExamples = `
    jaas upgrade-controller mycontroller
    jaas upgrade-controller mycontroller --target-version 3.6.8
    jaas upgrade-controller mycontroller --dry-run
`
)

// NewUpgradeControllerCommand returns a command to upgrade a backing controller's agent.
func NewUpgradeControllerCommand() cmd.Command {
	cmd := &upgradeControllerCommand{}
	cmd.SetClientStore(jujuclient.NewFileClientStore())
	return modelcmd.WrapBase(cmd)
}

type upgradeControllerCommand struct {
	jaasCommandBase

	controllerName      string
	targetVersionStr    string
	targetVersion       version.Number
	agentStream         string
	ignoreAgentVersions bool
	dryRun              bool
}

func (c *upgradeControllerCommand) Info() *cmd.Info {
	return jujucmd.Info(&cmd.Info{
		Name:     "upgrade-controller",
		Args:     "<controller-name>",
		Purpose:  "Upgrades the agent of a backing Juju controller",
		Doc:      upgradeControllerDoc,
		Examples: upgradeControllerExamples,
	})
}

func (c *upgradeControllerCommand) SetFlags(f *gnuflag.FlagSet) {
	c.CommandBase.SetFlags(f)
	f.StringVar(&c.targetVersionStr, "target-version", "", "Upgrade to this specific version")
	f.StringVar(&c.agentStream, "agent-stream", "", "Check this agent stream for upgrades")
	f.BoolVar(&c.ignoreAgentVersions, "ignore-agent-versions", false, "Don't check if all agents have already reached the current version")
	f.BoolVar(&c.dryRun, "dry-run", false, "Don't change anything, just report what version would be chosen")
}

func (c *upgradeControllerCommand) Init(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("controller name is required")
	}
	c.controllerName = args[0]

	if c.targetVersionStr != "" {
		v, err := version.Parse(c.targetVersionStr)
		if err != nil {
			return fmt.Errorf("invalid --target-version %q: %w", c.targetVersionStr, err)
		}
		c.targetVersion = v
	}

	return cmd.CheckEmpty(args[1:])
}

func (c *upgradeControllerCommand) Run(ctxt *cmd.Context) error {
	client, err := c.getJIMMAPI()
	if err != nil {
		return fmt.Errorf("failed to create JIMM client: %w", err)
	}
	defer client.Close()

	req := &apiparams.UpgradeControllerRequest{
		ControllerName:      c.controllerName,
		TargetVersion:       c.targetVersion,
		AgentStream:         c.agentStream,
		IgnoreAgentVersions: c.ignoreAgentVersions,
		DryRun:              c.dryRun,
	}

	resp, err := client.UpgradeController(req)
	if err != nil {
		return fmt.Errorf("upgrade-controller failed: %w", err)
	}

	if c.dryRun {
		ctxt.Infof("best version:\n    %v", resp.ChosenVersion)
		ctxt.Infof("upgrade-controller --dry-run: no changes applied")
	} else {
		fmt.Fprintf(ctxt.Stdout, "started upgrade to %s\n", resp.ChosenVersion)
	}
	return nil
}
