// Copyright 2025 Canonical.

package jujuclient

import (
	"context"

	"github.com/juju/juju/api/client/modelupgrader"
	"github.com/juju/juju/core/semversion"
)

// AbortModelUpgrade aborts and archives any in-progress upgrade on the given model.
func (c Connection) AbortModelUpgrade(ctx context.Context, modelUUID string) error {
	return modelupgrader.NewClient(&c).AbortModelUpgrade(ctx, modelUUID)
}

// UpgradeModel upgrades the model to the provided agent version.
// The provided target version could be version.Zero, in which case the
// best version is selected by the controller and returned as ChosenVersion
// in the result.
func (c Connection) UpgradeModel(
	ctx context.Context,
	modelUUID string,
	targetVersion semversion.Number,
	stream string,
	ignoreAgentVersions bool,
	dryRun bool,
) (semversion.Number, error) {
	return modelupgrader.NewClient(&c).UpgradeModel(ctx, modelUUID, targetVersion, stream, ignoreAgentVersions, dryRun)
}
