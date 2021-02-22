// Copyright 2020 Canonical Ltd.

// Package jimm contains the business logic used to manage clouds,
// cloudcredentials and models.
package jimm

import (
	"context"
	"time"

	vault "github.com/hashicorp/vault/api"
	jujuparams "github.com/juju/juju/apiserver/params"
	"github.com/juju/names/v4"
	"gopkg.in/macaroon-bakery.v2/bakery"

	"github.com/CanonicalLtd/jimm/internal/db"
	"github.com/CanonicalLtd/jimm/internal/dbmodel"
	"github.com/CanonicalLtd/jimm/internal/errors"
)

// A JIMM provides the buisness logic for managing resources in the JAAS
// system. A single JIMM instance is shared by all concurrent API
// connections therefore the JIMM object itself does not contain any per-
// request state.
type JIMM struct {
	// Database is the database used by JIMM, this provides direct access
	// to the data store. Any client accessing the database directly is
	// responsible for ensuring that the authenticated user has access to
	// the data.
	Database db.Database

	// Authenticator is the authenticator JIMM uses to determine the user
	// authenticating with the API. If this is not specified then all
	// authentication requests are considered to have failed.
	Authenticator Authenticator

	// Dialer is the API dialer JIMM uses to contact juju controllers. if
	// this is not configured all connection attempts will fail.
	Dialer Dialer

	// VaultClient is the client for a vault server that is used to store
	// secrets.
	VaultClient *vault.Client

	// VaultPath is the root path in the vault for JIMM's secrets.
	VaultPath string
}

// An Authenticator authenticates login requests.
type Authenticator interface {
	// Authenticate processes the given LoginRequest and returns the user
	// that has authenticated.
	Authenticate(ctx context.Context, req *jujuparams.LoginRequest) (*dbmodel.User, error)
}

// dial dials the controller and model specified by the given Controller
// and ModelTag. If no Dialer has been configured then an error with a
// code of CodeConnectionFailed will be returned.
func (j *JIMM) dial(ctx context.Context, ctl *dbmodel.Controller, modelTag names.ModelTag) (API, error) {
	if j == nil || j.Dialer == nil {
		return nil, errors.E(errors.CodeConnectionFailed, "no dialer configured")
	}
	return j.Dialer.Dial(ctx, ctl, modelTag)
}

// A Dialer provides a connection to a controller.
type Dialer interface {
	// Dial creates an API connection to a controller. If the given
	// model-tag is non-zero the connection will be to that model,
	// otherwise the connection is to the controller. After sucessfully
	// dialing the controller the UUID, AgentVersion and HostPorts fields
	// in the given controller should be updated to the values provided
	// by the controller.
	Dial(ctx context.Context, ctl *dbmodel.Controller, modelTag names.ModelTag) (API, error)
}

// An API is the interface JIMM uses to access the API on a controller.
type API interface {
	// AddCloud adds a new cloud.
	AddCloud(context.Context, names.CloudTag, jujuparams.Cloud) error

	// CheckCredentialModels checks that an updated credential can be used
	// with the associated models.
	CheckCredentialModels(context.Context, jujuparams.TaggedCredential) ([]jujuparams.UpdateCredentialModelResult, error)

	// Close closes the API connection.
	Close() error

	// Cloud fetches the cloud data for the given cloud.
	Cloud(context.Context, names.CloudTag, *jujuparams.Cloud) error

	// CloudInfo fetches the cloud information for the cloud with the given
	// tag.
	CloudInfo(context.Context, names.CloudTag, *jujuparams.CloudInfo) error

	// Clouds returns the set of clouds supported by the controller.
	Clouds(context.Context) (map[names.CloudTag]jujuparams.Cloud, error)

	// ControllerModelSummary fetches the model summary of the model on the
	// controller that hosts the controller machines.
	ControllerModelSummary(context.Context, *jujuparams.ModelSummary) error

	// CreateModel creates a new model.
	CreateModel(context.Context, *jujuparams.ModelCreateArgs, *jujuparams.ModelInfo) error

	// DestroyApplicationOffer destroys an application offer.
	DestroyApplicationOffer(context.Context, string, bool) error

	// DestroyModel destroys a model.
	DestroyModel(context.Context, names.ModelTag, *bool, *bool, *time.Duration) error

	// FindApplicationOffers finds application offers that match the
	// filter.
	FindApplicationOffers(context.Context, []jujuparams.OfferFilter) ([]jujuparams.ApplicationOfferAdminDetails, error)

	// GetApplicationOffer completes the given ApplicationOfferAdminDetails
	// structure.
	GetApplicationOffer(context.Context, *jujuparams.ApplicationOfferAdminDetails) error

	// GetApplicationOfferConsumeDetails gets the details required to
	// consume an application offer
	GetApplicationOfferConsumeDetails(context.Context, names.UserTag, *jujuparams.ConsumeOfferDetails, bakery.Version) error

	// GrantApplicationOfferAccess grants access to an application offer to
	// a user.
	GrantApplicationOfferAccess(context.Context, string, names.UserTag, jujuparams.OfferAccessPermission) error

	// GrantCloudAccess grants cloud access to a user.
	GrantCloudAccess(context.Context, names.CloudTag, names.UserTag, string) error

	// GrantJIMMModelAdmin makes the JIMM user an admin on a model.
	GrantJIMMModelAdmin(context.Context, names.ModelTag) error

	// GrantModelAccess grants model access to a user.
	GrantModelAccess(context.Context, names.ModelTag, names.UserTag, jujuparams.UserAccessPermission) error

	// ListApplicationOffers lists application offers that match the
	// filter.
	ListApplicationOffers(context.Context, []jujuparams.OfferFilter) ([]jujuparams.ApplicationOfferAdminDetails, error)

	// ModelInfo fetches a model's ModelInfo.
	ModelInfo(context.Context, *jujuparams.ModelInfo) error

	// ModelStatus fetches a model's ModelStatus.
	ModelStatus(context.Context, *jujuparams.ModelStatus) error

	// ModelSummaryWatcherNext returns the next set of model summaries from
	// the watcher.
	ModelSummaryWatcherNext(context.Context, string) ([]jujuparams.ModelAbstract, error)

	// ModelSummaryWatcherStop stops a model summary watcher.
	ModelSummaryWatcherStop(context.Context, string) error

	// Offer creates a new application-offer.
	Offer(context.Context, jujuparams.AddApplicationOffer) error

	// RemoveCloud removes a cloud.
	RemoveCloud(context.Context, names.CloudTag) error

	// RevokeApplicationOfferAccess revokes access to an application offer
	// from a user.
	RevokeApplicationOfferAccess(context.Context, string, names.UserTag, jujuparams.OfferAccessPermission) error

	// RevokeCloudAccess revokes cloud access from a user.
	RevokeCloudAccess(context.Context, names.CloudTag, names.UserTag, string) error

	// RevokeCredential revokes a credential.
	RevokeCredential(context.Context, names.CloudCredentialTag) error

	// RevokeModelAccess revokes model access from a user.
	RevokeModelAccess(context.Context, names.ModelTag, names.UserTag, jujuparams.UserAccessPermission) error

	// SupportsCheckCredentialModels returns true if the
	// CheckCredentialModels method can be used.
	SupportsCheckCredentialModels() bool

	// SupportsModelSummaryWatcher returns true if the connection supports
	// a ModelSummaryWatcher.
	SupportsModelSummaryWatcher() bool

	// UpdateCredential updates a credential.
	UpdateCredential(context.Context, jujuparams.TaggedCredential) ([]jujuparams.UpdateCredentialModelResult, error)

	// ValidateModelUpgrade validates that a model can be upgraded.
	ValidateModelUpgrade(context.Context, names.ModelTag, bool) error

	// WatchAllModelSummaries creates a ModelSummaryWatcher.
	WatchAllModelSummaries(context.Context) (string, error)
}