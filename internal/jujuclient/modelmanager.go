// Copyright 2026 Canonical.

package jujuclient

import (
	"context"
	"time"

	"github.com/juju/juju/api/base"
	"github.com/juju/juju/api/client/modelmanager"
	jujuparams "github.com/juju/juju/rpc/params"
	"github.com/juju/names/v6"

	"github.com/canonical/jimm/v3/internal/errors"
)

// CreateModelArgs holds the arguments for creating a model.
type CreateModelArgs struct {
	Name               string
	Owner              string
	Cloud              string
	CloudRegion        string
	CloudCredentialTag names.CloudCredentialTag
	Config             map[string]any
}

// CreateModel creates a new model as specified by the given model
// specification returning the model details created. CreateModel
// uses the Create model procedure on the ModelManager facade.
func (c Connection) CreateModel(ctx context.Context, args *CreateModelArgs) (base.ModelInfo, error) {
	return modelmanager.NewClient(&c).CreateModel(ctx,
		args.Name,
		names.NewUserTag(args.Owner),
		args.Cloud,
		args.CloudRegion,
		args.CloudCredentialTag,
		args.Config)
}

// ModelMigrationStatus holds the migration status of a model.
type ModelMigrationStatus struct {
	Status string
	Start  *time.Time
	End    *time.Time
}

// SupportedFeature represents jujuparams.SupportedFeature.
type SupportedFeature struct {
	Name        string
	Description string
	Version     string
}

// SecretBackend represents jujuparams.SecretBackend.
type SecretBackend struct {
	Name                string
	BackendType         string
	TokenRotateInterval *time.Duration
	Config              map[string]any
}

// SecretBackendResult represents jujuparams.SecretBackendResult.
type SecretBackendResult struct {
	Result     SecretBackend
	ID         string
	NumSecrets int
	Status     string
	Message    string
	Error      error
}

// ModelInfo holds information about a model.
// It combines the base.ModelInfo returned by the Juju client in other API methods with additional
// information that is contained in the params.ModelInfo returned by the ModelInfo API call.
type ModelInfo struct {
	base.ModelInfo
	MigrationStatus         *ModelMigrationStatus
	CloudCredentialValidity *bool
	SupportedFeatures       []SupportedFeature
	SecretBackends          []SecretBackendResult
}

// ModelInfo retrieves information about a model from the controller.
func (c Connection) ModelInfo(ctx context.Context, model names.ModelTag) (ModelInfo, error) {
	res, err := modelmanager.NewClient(&c).ModelInfo(ctx, []names.ModelTag{model})
	if err != nil {
		return ModelInfo{}, err
	}
	if res[0].Error != nil {
		return ModelInfo{}, res[0].Error
	}
	return convertParamsModelInfo(*res[0].Result)
}

// GrantJIMMModelAdmin ensures that the JIMM user is an admin level user
// of the given model. This is a specialized wrapper around
// ModifyModelAccess to be used when bootstrapping a model. Any error
// that is returned from the API will be of type *APIError.
// GrantJIMMModelAdmin uses the ModifyModelAccess procedure on the
// ModelManager facade.
func (c Connection) GrantJIMMModelAdmin(ctx context.Context, tag names.ModelTag) error {
	access := string(jujuparams.ModelAdminAccess)
	return modelmanager.NewClient(&c).GrantModel(ctx, c.dialer.AdminUsername, access, tag.Id())
}

// DumpModel dumps debugging details for the given model. If the simplied
// dump is requested then a simplified dump is returned. DumpModel uses the
// DumpModels method on the ModelManager facade.
func (c Connection) DumpModel(ctx context.Context, tag names.ModelTag) (map[string]any, error) {
	return modelmanager.NewClient(&c).DumpModel(ctx, tag)
}

// DumpModelDB dumps the controller database entry given model.
// DumpModelDB uses the DumpModelsDB method on the ModelManager facade..
func (c Connection) DumpModelDB(ctx context.Context, tag names.ModelTag) (map[string]any, error) {
	return modelmanager.NewClient(&c).DumpModelDB(ctx, tag)
}

// ControllerModelSummary retrieves the ModelSummary for the controller
// model. ControllerModelSummary uses the ListModelSummaries procedure on
// the ModelManager facade.
func (c Connection) ControllerModelSummary(ctx context.Context) (base.UserModelSummary, error) {
	modelSummaries, err := modelmanager.NewClient(&c).ListModelSummaries(ctx, c.user.ResourceTag().String(), true)
	if err != nil {
		return base.UserModelSummary{}, err
	}
	for _, r := range modelSummaries {
		if r.IsController {
			return r, nil
		}
	}
	return base.UserModelSummary{}, errors.Codef(errors.CodeNotFound, "controller model not found")
}

// ListModelSummaries retrieves the list of model summaries from the controler
func (c Connection) ListModelSummaries(ctx context.Context, ms jujuparams.ModelSummariesRequest) ([]base.UserModelSummary, error) {
	return modelmanager.NewClient(&c).ListModelSummaries(ctx, c.user.ResourceTag().String(), ms.All)
}

// ValidateModelUpgrade validates if a model is allowed to perform an upgrade. It
// uses ValidateModelUpgrades on the ModelManager facade.
func (c Connection) ValidateModelUpgrade(ctx context.Context, model names.ModelTag, force bool) error {
	return modelmanager.NewClient(&c).ValidateModelUpgrade(ctx, model, force)
}

// DestroyModel starts the destruction of the given model.
func (c Connection) DestroyModel(ctx context.Context, tag names.ModelTag, destroyStorage *bool, force *bool, maxWait, timeout *time.Duration) error {
	return modelmanager.NewClient(&c).DestroyModel(ctx, tag, destroyStorage, force, maxWait, timeout)
}

// ModelStatus retrieves the status of a model from the controller.
func (c Connection) ModelStatus(ctx context.Context, modelTag names.ModelTag) (base.ModelStatus, error) {
	statuses, err := modelmanager.NewClient(&c).ModelStatus(ctx, modelTag)
	if err != nil {
		return base.ModelStatus{}, err
	}
	if len(statuses) == 0 {
		return base.ModelStatus{}, errors.New("no status returned for model")
	}
	if statuses[0].Error != nil {
		return base.ModelStatus{}, statuses[0].Error
	}
	return statuses[0], nil
}

// ChangeModelCredential replaces cloud credential for a given model with the provided one.
func (c Connection) ChangeModelCredential(ctx context.Context, model names.ModelTag, credential names.CloudCredentialTag) error {
	return modelmanager.NewClient(&c).ChangeModelCredential(ctx, model, credential)
}

// ListModels returns UserModel's for the user that is logged in. If the user logged
// in is "admin" they may specify another user's models.
//
// In our wrapper, we ask as the controller admin. So expect ALL models from
// the controller.
func (c Connection) ListModels(ctx context.Context) ([]base.UserModel, error) {
	return modelmanager.NewClient(&c).ListModels(ctx, "admin")
}
