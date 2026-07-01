// Copyright 2026 Canonical.

package jujuclient

import (
	"context"

	"github.com/juju/juju/api/client/modelconfig"
	"github.com/juju/juju/api/controller/controller"
	jujucontroller "github.com/juju/juju/controller"
	"github.com/juju/juju/environs/cloudspec"
	"github.com/juju/juju/environs/config"
	"github.com/juju/names/v5"
)

// ControllerConfig retrieves the controller configuration.
func (c Connection) ControllerConfig(ctx context.Context) (jujucontroller.Config, error) {
	return controller.NewClient(&c).ControllerConfig()
}

// ControllerModelUUID returns the UUID of the controller model on the
// connected controller. The connection must be scoped to the controller
// (not a specific model), in which case ModelGet returns the controller
// model's configuration.
func (c Connection) ControllerModelUUID(ctx context.Context) (string, error) {
	attrs, err := modelconfig.NewClient(&c).ModelGet()
	if err != nil {
		return "", err
	}

	cfg, err := config.New(config.NoDefaults, attrs)
	if err != nil {
		return "", err
	}

	return cfg.UUID(), nil
}

// CloudSpec retrieves the cloud spec of the model connected to.
func (c Connection) CloudSpec(ctx context.Context) (cloudspec.CloudSpec, error) {
	modelCfgClient := modelconfig.NewClient(&c)
	attrs, err := modelCfgClient.ModelGet()
	if err != nil {
		return cloudspec.CloudSpec{}, err
	}

	cfg, err := config.New(config.NoDefaults, attrs)
	if err != nil {
		return cloudspec.CloudSpec{}, err
	}

	controllerClient := controller.NewClient(&c)
	return controllerClient.CloudSpec(names.NewModelTag(cfg.UUID()))
}
