// Copyright 2026 Canonical.

package cmd

import (
	"fmt"

	"github.com/juju/cmd/v3"
	"github.com/juju/gnuflag"
	jujucmd "github.com/juju/juju/cmd"
	"github.com/juju/juju/cmd/modelcmd"
	"github.com/juju/juju/jujuclient"
	"github.com/juju/names/v5"

	apiparams "github.com/canonical/jimm/v3/pkg/api/params"
)

const (
	recoverModelCredentialCommandDoc = `
Recovers a lost cloud credential (for example after a Vault outage) by fetching
the credential's secret contents from a controller that hosts a model using the
credential, and storing them back into JIMM's credential store.

This is a disaster-recovery operation and requires JIMM admin access. For a
credential to be recoverable:
  - its metadata must still exist in JIMM's database,
  - at least one model must still be using it, and
  - the controller hosting that model must be reachable and must still return
    the credential's secrets (some providers, e.g. LXD 'certificate'
    credentials, never expose secrets over the API and cannot be recovered).

Only cloud credentials can be recovered this way. Controller credentials (the
login JIMM uses to reach a Juju controller) cannot be read back from the
controller and must be reset separately.

The credential is identified either by its short form "<cloud>/<owner>/<name>"
or by its full tag "cloudcred-<cloud>_<owner>_<name>".

Use --all to recover every cloud credential known to JIMM in one pass.

Use --dry-run to verify that credentials can be fetched from their controllers
without actually writing anything back to JIMM's credential store. The output
shows which credentials would be recovered.
`
	recoverModelCredentialCommandExample = `
    jaas recover-model-credential aws/alice@canonical.com/default
    jaas recover-model-credential cloudcred-aws_alice@canonical.com_default
    jaas recover-model-credential --all
    jaas recover-model-credential --all --dry-run
`
)

// NewRecoverModelCredentialCommand returns a command to recover a lost cloud credential.
func NewRecoverModelCredentialCommand() cmd.Command {
	cmd := &recoverModelCredentialCommand{}
	cmd.SetClientStore(jujuclient.NewFileClientStore())

	return modelcmd.WrapBase(cmd)
}

// recoverModelCredentialCommand recovers a lost cloud credential.
type recoverModelCredentialCommand struct {
	jaasCommandBase

	req apiparams.RecoverModelCredentialRequest
}

// Info implements the cmd.Command interface.
func (c *recoverModelCredentialCommand) Info() *cmd.Info {
	return jujucmd.Info(&cmd.Info{
		Name:     "recover-model-credential",
		Args:     "[<cloud>/<owner>/<name>]",
		Purpose:  "Recover a lost cloud credential from a controller.",
		Doc:      recoverModelCredentialCommandDoc,
		Examples: recoverModelCredentialCommandExample,
	})
}

// SetFlags implements Command.SetFlags.
func (c *recoverModelCredentialCommand) SetFlags(f *gnuflag.FlagSet) {
	c.CommandBase.SetFlags(f)
	f.BoolVar(&c.req.All, "all", false, "recover every cloud credential known to JIMM")
	f.BoolVar(&c.req.DryRun, "dry-run", false, "check that credentials can be fetched without writing them back")
}

// Init implements the cmd.Command interface.
func (c *recoverModelCredentialCommand) Init(args []string) error {
	if c.req.All {
		if len(args) > 0 {
			return fmt.Errorf("no arguments allowed when --all is specified")
		}
		return nil
	}

	switch len(args) {
	default:
		return fmt.Errorf("too many args")
	case 0:
		return fmt.Errorf("cloud credential tag not specified (or use --all)")
	case 1:
	}

	if !names.IsValidCloudCredential(args[0]) {
		// Also accept a full tag string (cloudcred-...).
		if _, err := names.ParseCloudCredentialTag(args[0]); err != nil {
			return fmt.Errorf("invalid cloud credential tag %q", args[0])
		}
		c.req.CredentialTag = args[0]
		return nil
	}
	c.req.CredentialTag = names.NewCloudCredentialTag(args[0]).String()
	return nil
}

// Run implements Command.Run.
func (c *recoverModelCredentialCommand) Run(ctxt *cmd.Context) error {
	jimmAPI, err := c.getJIMMAPI()
	if err != nil {
		return fmt.Errorf("could not create JIMM API client: %w", err)
	}
	defer jimmAPI.Close()

	if c.req.DryRun {
		fmt.Fprintln(ctxt.Stdout, "Dry run — no credentials will be written back to JIMM's credential store.")
	}

	resp, err := jimmAPI.RecoverModelCredential(&c.req)
	if err != nil {
		return fmt.Errorf("could not recover model credential: %w", err)
	}

	var failed int
	for _, res := range resp.Results {
		if res.Recovered {
			if c.req.DryRun {
				fmt.Fprintf(ctxt.Stdout, "would recover: %s\n", res.CredentialTag)
			} else {
				fmt.Fprintf(ctxt.Stdout, "recovered: %s\n", res.CredentialTag)
			}
		} else {
			failed++
			fmt.Fprintf(ctxt.Stderr, "failed:    %s: %s\n", res.CredentialTag, res.Error)
		}
	}

	if c.req.All {
		if c.req.DryRun {
			fmt.Fprintf(ctxt.Stdout, "\n%d would be recovered, %d failed\n", len(resp.Results)-failed, failed)
		} else {
			fmt.Fprintf(ctxt.Stdout, "\n%d recovered, %d failed\n", len(resp.Results)-failed, failed)
		}
	}
	if failed > 0 {
		return cmd.ErrSilent
	}
	return nil
}
