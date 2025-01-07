// Copyright 2025 Canonical.

// Package jimm contains the business logic used to manage clouds,
// cloudcredentials and models.
package jimm

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"
	"github.com/google/uuid"
	"github.com/juju/juju/api/base"
	"github.com/juju/juju/core/crossmodel"
	jujuparams "github.com/juju/juju/rpc/params"
	"github.com/juju/names/v5"
	"github.com/juju/zaputil/zapctx"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"

	"github.com/canonical/jimm/v3/internal/common/pagination"
	"github.com/canonical/jimm/v3/internal/db"
	"github.com/canonical/jimm/v3/internal/dbmodel"
	"github.com/canonical/jimm/v3/internal/errors"
	"github.com/canonical/jimm/v3/internal/jimm/credentials"
	"github.com/canonical/jimm/v3/internal/jimm/group"
	"github.com/canonical/jimm/v3/internal/jimm/identity"
	"github.com/canonical/jimm/v3/internal/jimm/login"
	"github.com/canonical/jimm/v3/internal/jimm/role"
	"github.com/canonical/jimm/v3/internal/jimmjwx"
	"github.com/canonical/jimm/v3/internal/openfga"
	ofganames "github.com/canonical/jimm/v3/internal/openfga/names"
	"github.com/canonical/jimm/v3/internal/pubsub"
)

var (
	initiateMigration = func(ctx context.Context, j *JIMM, user *openfga.User, spec jujuparams.MigrationSpec) (jujuparams.InitiateMigrationResult, error) {
		return j.InitiateMigration(ctx, user, spec)
	}
)

// OAuthAuthenticator is responsible for handling authentication
// via OAuth2.0 AND JWT access tokens to JIMM.
type OAuthAuthenticator interface {
	// Device initiates a device flow login and is step ONE of TWO.
	//
	// This is done via retrieving a:
	// - Device code
	// - User code
	// - VerificationURI
	// - Interval
	// - Expiry
	// From the device /auth endpoint.
	//
	// The verification uri and user code is sent to the user, as they must enter the code
	// into the uri.
	//
	// The interval, expiry and device code and used to poll the token endpoint for completion.
	Device(ctx context.Context) (*oauth2.DeviceAuthResponse, error)

	// DeviceAccessToken continues and collect an access token during the device login flow
	// and is step TWO.
	//
	// See Device(...) godoc for more info pertaining to the flow.
	DeviceAccessToken(ctx context.Context, res *oauth2.DeviceAuthResponse) (*oauth2.Token, error)

	// ExtractAndVerifyIDToken extracts the id token from the extras claims of an oauth2 token
	// and performs signature verification of the token.
	ExtractAndVerifyIDToken(ctx context.Context, oauth2Token *oauth2.Token) (*oidc.IDToken, error)

	// Email retrieves the users email from an id token via the email claim
	Email(idToken *oidc.IDToken) (string, error)

	// MintSessionToken mints a session token to be used when logging into JIMM
	// via an access token. The token only contains the user's email for authentication.
	MintSessionToken(email string) (string, error)

	// VerifySessionToken symmetrically verifies the validty of the signature on the
	// access token JWT, returning the parsed token.
	//
	// The subject of the token contains the user's email and can be used
	// for user object creation.
	// If verification fails, return error with code CodeInvalidSessionToken
	// to indicate to the client to retry login.
	VerifySessionToken(token string) (jwt.Token, error)

	// UpdateIdentity updates the database with the display name and access token set for the user.
	// And, if present, a refresh token.
	UpdateIdentity(ctx context.Context, email string, token *oauth2.Token) error

	// VerifyClientCredentials verifies the provided client ID and client secret.
	VerifyClientCredentials(ctx context.Context, clientID string, clientSecret string) error

	// AuthenticateBrowserSession updates the session for a browser, additionally
	// retrieving new access tokens upon expiry. If this cannot be done, the cookie
	// is deleted and an error is returned.
	AuthenticateBrowserSession(ctx context.Context, w http.ResponseWriter, req *http.Request) (context.Context, error)
}

// RoleManager provides a means to manage roles within JIMM.
type RoleManager interface {
	// AddRole adds a role to JIMM.
	AddRole(ctx context.Context, user *openfga.User, roleName string) (*dbmodel.RoleEntry, error)
	// GetRoleByUUID returns a role based on the provided UUID.
	GetRoleByUUID(ctx context.Context, user *openfga.User, uuid string) (*dbmodel.RoleEntry, error)
	// GetRoleByName returns a role based on the provided name.
	GetRoleByName(ctx context.Context, user *openfga.User, name string) (*dbmodel.RoleEntry, error)
	// RemoveRole removes the role from JIMM in both the store and authorisation store.
	RemoveRole(ctx context.Context, user *openfga.User, roleName string) error
	// RenameRole renames a role in JIMM's DB.
	RenameRole(ctx context.Context, user *openfga.User, uuid, newName string) error
	// ListRoles returns a list of roles known to JIMM.
	// `match` will filter the list fuzzy matching role's name or uuid.
	ListRoles(ctx context.Context, user *openfga.User, pagination pagination.LimitOffsetPagination, match string) ([]dbmodel.RoleEntry, error)
	// CountRoles returns the number of roles that exist.
	CountRoles(ctx context.Context, user *openfga.User) (int, error)
}

// GroupManager provides a means to manage groups within JIMM.
type GroupManager interface {
	// AddGroup adds a role to JIMM.
	AddGroup(ctx context.Context, user *openfga.User, roleName string) (*dbmodel.GroupEntry, error)
	// GetGroupByUUID returns a role based on the provided UUID.
	GetGroupByUUID(ctx context.Context, user *openfga.User, uuid string) (*dbmodel.GroupEntry, error)
	// GetGroupByName returns a role based on the provided name.
	GetGroupByName(ctx context.Context, user *openfga.User, name string) (*dbmodel.GroupEntry, error)
	// RemoveGroup removes the role from JIMM in both the store and authorisation store.
	RemoveGroup(ctx context.Context, user *openfga.User, roleName string) error
	// RenameGroup renames a role in JIMM's DB.
	RenameGroup(ctx context.Context, user *openfga.User, uuid, newName string) error
	// ListGroups returns a list of roles known to JIMM.
	// `match` will filter the list fuzzy matching role's name or uuid.
	ListGroups(ctx context.Context, user *openfga.User, pagination pagination.LimitOffsetPagination, match string) ([]dbmodel.GroupEntry, error)
	// CountGroups returns the number of roles that exist.
	CountGroups(ctx context.Context, user *openfga.User) (int, error)
}

// IdentityManager provides a means to fetch identities in JIMM.
// Identities cannot be created here, that can only be done via login.
type IdentityManager interface {
	FetchIdentity(ctx context.Context, id string) (*openfga.User, error)
	ListIdentities(ctx context.Context, user *openfga.User, pagination pagination.LimitOffsetPagination, match string) ([]openfga.User, error)
	CountIdentities(ctx context.Context, user *openfga.User) (int, error)
}

// LoginManager provides methods for login/authentication and creates identities (users).
type LoginManager interface {
	// AuthenticateBrowserSession authenticates a browser login.
	AuthenticateBrowserSession(ctx context.Context, w http.ResponseWriter, req *http.Request) (context.Context, error)
	// LoginDevice starts the device login flow.
	LoginDevice(ctx context.Context) (*oauth2.DeviceAuthResponse, error)
	// GetDeviceSessionToken returns a session token scoped to the user's identity.
	GetDeviceSessionToken(ctx context.Context, deviceOAuthResponse *oauth2.DeviceAuthResponse) (string, error)
	// LoginClientCredentials logs in a user with client credentials.
	LoginClientCredentials(ctx context.Context, clientID string, clientSecret string) (*openfga.User, error)
	// LoginWithSessionToken logs in a user with a session token.
	LoginWithSessionToken(ctx context.Context, sessionToken string) (*openfga.User, error)
	// LoginWithSessionCookie logs in a user assuming cookie auth was done previously.
	LoginWithSessionCookie(ctx context.Context, identityID string) (*openfga.User, error)
	// UserLogin creates/fetches an identity based on the identity provided and returns an openfga user object.
	UserLogin(ctx context.Context, identity string) (*openfga.User, error)
}

// Parameters holds the services and static fields passed to the jimm.New() constructor.
// You can provide mock implementations of certain services where necessary for dependency injection.
type Parameters struct {
	// Database is the database used by JIMM, this provides direct access
	// to the data store. Any client accessing the database directly is
	// responsible for ensuring that the authenticated user has access to
	// the data.
	Database *db.Database

	// Dialer is the API dialer JIMM uses to contact juju controllers. if
	// this is not configured all connection attempts will fail.
	Dialer Dialer

	// CredentialStore is a store for the attributes of a
	// cloud credential and controller credentials. If this is
	// not configured then the attributes
	// are stored in the standard database.
	CredentialStore credentials.CredentialStore

	// Pubsub is a pub-sub hub used for buffering model summaries.
	Pubsub *pubsub.Hub

	// ReservedCloudNames is the list of names that cannot be used for
	// hosted clouds. If this is empty then DefaultReservedCloudNames
	// is used.
	ReservedCloudNames []string

	// UUID holds the UUID of the JIMM controller.
	UUID string

	// OpenFGAClient holds the client used to interact
	// with the OpenFGA ReBAC system.
	OpenFGAClient *openfga.OFGAClient

	// JWTService is responsible for minting JWTs to access controllers.
	JWTService *jimmjwx.JWTService

	// OAuthAuthenticator is responsible for handling authentication
	// via OAuth2.0 AND JWT access tokens to JIMM.
	OAuthAuthenticator OAuthAuthenticator
}

func (p *Parameters) Validate() error {
	if p.Database == nil {
		return errors.E("missing database")
	}

	if p.Dialer == nil {
		return errors.E("missing dialer")
	}

	if p.CredentialStore == nil {
		return errors.E("missing credential store")
	}

	if p.Pubsub == nil {
		return errors.E("missing pubsub hub")
	}

	if p.UUID == "" {
		return errors.E("missing uuid")
	}

	if p.OpenFGAClient == nil {
		return errors.E("missing openfga client")
	}

	if p.JWTService == nil {
		return errors.E("missing jwt service")
	}

	if p.OAuthAuthenticator == nil {
		return errors.E("missing oauth authenticator")
	}

	return nil
}

// New returns a new instance of JIMM.
// See [Option] and [Parameters] to better understand how to perform dependency injection.
// Primitives like the dialer or authentication service can be mocked at a low level,
// alternatively top business layer objects like the RoleManager can be mocked instead.
func New(p Parameters) (*JIMM, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	j := &JIMM{
		Parameters: p,
	}

	if err := j.Database.Migrate(context.Background()); err != nil {
		return nil, errors.E(err)
	}

	roleManager, err := role.NewRoleManager(j.Database, j.OpenFGAClient)
	if err != nil {
		return nil, err
	}
	j.roleManager = roleManager

	groupManager, err := group.NewGroupManager(j.Database, j.OpenFGAClient)
	if err != nil {
		return nil, err
	}
	j.groupManager = groupManager

	identityManager, err := identity.NewIdentityManager(j.Database, j.OpenFGAClient)
	if err != nil {
		return nil, err
	}
	j.identityManager = identityManager

	loginManager, err := login.NewLoginManager(j.Database, j.OpenFGAClient, j.OAuthAuthenticator, j.ResourceTag())
	if err != nil {
		return nil, err
	}
	j.loginManager = loginManager

	return j, nil
}

// A JIMM provides the business logic for managing resources in the JAAS
// system. A single JIMM instance is shared by all concurrent API
// connections therefore the JIMM object itself does not contain any per-
// request state.
type JIMM struct {
	Parameters

	// roleManager provides a means to manage roles within JIMM.
	roleManager RoleManager

	// groupManager provides a means to manage groups within JIMM.
	groupManager GroupManager

	// identityManager provides a means to manage identities within JIMM.
	identityManager IdentityManager

	// loginManager provides a means to authenticate and login/create users/identities within JIMM.
	loginManager LoginManager
}

// ResourceTag returns JIMM's controller tag stating its UUID.
func (j *JIMM) ResourceTag() names.ControllerTag {
	return names.NewControllerTag(j.UUID)
}

// PubsubHub returns the pub-sub hub used for buffering model summaries.
func (j *JIMM) PubSubHub() *pubsub.Hub {
	return j.Pubsub
}

// RoleManager returns a manager that enables role management.
func (j *JIMM) RoleManager() RoleManager {
	return j.roleManager
}

// GroupManager returns a manager that enables group management.
func (j *JIMM) GroupManager() GroupManager {
	return j.groupManager
}

// IdentityManager returns a manager that enables identity (user/service-account) management.
func (j *JIMM) IdentityManager() IdentityManager {
	return j.identityManager
}

// Login manager returns a manager that enables login and authentication.
func (j *JIMM) LoginManager() LoginManager {
	return j.loginManager
}

type permission struct {
	resource string
	relation string
}

// dial dials the controller and model specified by the given Controller
// and ModelTag. If no Dialer has been configured then an error with a
// code of CodeConnectionFailed will be returned.
func (j *JIMM) dial(ctx context.Context, ctl *dbmodel.Controller, modelTag names.ModelTag, permissons ...permission) (API, error) {
	if j == nil || j.Dialer == nil {
		return nil, errors.E(errors.CodeConnectionFailed, "no dialer configured")
	}
	var permissionMap map[string]string
	if len(permissons) > 0 {
		permissionMap = make(map[string]string, len(permissons))
		for _, p := range permissons {
			permissionMap[p.resource] = p.relation
		}
	}

	return j.Dialer.Dial(ctx, ctl, modelTag, permissionMap)
}

// A Dialer provides a connection to a controller.
type Dialer interface {
	// Dial creates an API connection to a controller. If the given
	// model-tag is non-zero the connection will be to that model,
	// otherwise the connection is to the controller. After successfully
	// dialing the controller the UUID, AgentVersion and HostPorts fields
	// in the given controller should be updated to the values provided
	// by the controller.
	Dial(ctx context.Context, ctl *dbmodel.Controller, modelTag names.ModelTag, requiredPermissions map[string]string) (API, error)
}

// An API is the interface JIMM uses to access the API on a controller.
type API interface {
	// API implements the base.APICallCloser so that we can
	// use the juju api clients to interact with juju controllers.
	base.APICallCloser

	// AddCloud adds a new cloud.
	AddCloud(context.Context, names.CloudTag, jujuparams.Cloud, bool) error

	// ChangeModelCredential replaces cloud credential for a given model with the provided one.
	ChangeModelCredential(context.Context, names.ModelTag, names.CloudCredentialTag) error

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
	DestroyModel(context.Context, names.ModelTag, *bool, *bool, *time.Duration, *time.Duration) error

	// ConnectStream creates a new connection to a streaming endpoint.
	ConnectStream(string, url.Values) (base.Stream, error)

	// DumpModel collects a database-agnostic dump of a model.
	DumpModel(context.Context, names.ModelTag, bool) (string, error)

	// DumpModelDB collects a database dump of a model.
	DumpModelDB(context.Context, names.ModelTag) (map[string]interface{}, error)

	// FindApplicationOffers finds application offers that match the
	// filter.
	FindApplicationOffers(context.Context, []jujuparams.OfferFilter) ([]jujuparams.ApplicationOfferAdminDetailsV5, error)

	// GetApplicationOffer completes the given ApplicationOfferAdminDetails
	// structure.
	GetApplicationOffer(context.Context, *jujuparams.ApplicationOfferAdminDetailsV5) error

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

	// IsBroken returns true if the API connection has failed.
	IsBroken() bool

	// ListApplicationOffers lists application offers that match the
	// filter.
	ListApplicationOffers(context.Context, []jujuparams.OfferFilter) ([]jujuparams.ApplicationOfferAdminDetailsV5, error)

	// ListModelSummaries lists models summaries
	ListModelSummaries(context.Context, jujuparams.ModelSummariesRequest) (jujuparams.ModelSummaryResults, error)

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
	Offer(context.Context, crossmodel.OfferURL, jujuparams.AddApplicationOffer) error

	// Ping tests the connection is working.
	Ping(context.Context) error

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

	// Status returns the status of the juju model.
	Status(ctx context.Context, patterns []string) (*jujuparams.FullStatus, error)

	// UpdateCloud updates a cloud definition.
	UpdateCloud(context.Context, names.CloudTag, jujuparams.Cloud) error

	// UpdateCredential updates a credential.
	UpdateCredential(context.Context, jujuparams.TaggedCredential) ([]jujuparams.UpdateCredentialModelResult, error)

	// ValidateModelUpgrade validates that a model can be upgraded.
	ValidateModelUpgrade(context.Context, names.ModelTag, bool) error

	// WatchAllModelSummaries creates a ModelSummaryWatcher.
	WatchAllModelSummaries(context.Context) (string, error)

	// ListFilesystems lists filesystems for desired machines.
	// If no machines provided, a list of all filesystems is returned.
	ListFilesystems(ctx context.Context, machines []string) ([]jujuparams.FilesystemDetailsListResult, error)

	// ListVolumes lists volumes for desired machines.
	// If no machines provided, a list of all volumes is returned.
	ListVolumes(ctx context.Context, machines []string) ([]jujuparams.VolumeDetailsListResult, error)

	// ListStorageDetails lists all storage.
	ListStorageDetails(ctx context.Context) ([]jujuparams.StorageDetails, error)

	// ListModels returns all UserModel's on the controller.
	ListModels(ctx context.Context) ([]base.UserModel, error)
}

// forEachController runs a given function on multiple controllers
// simultaneously. A connection is established to every controller in the
// given list concurrently and then the given function is called with the
// controller and API connection to use to perform the controller
// operation. ForEachConnection waits until all operations have finished
// before returning, any error returned will be the first error
// encountered when connecting to the controller or returned from the given
// function.
func (j *JIMM) forEachController(ctx context.Context, controllers []dbmodel.Controller, f func(*dbmodel.Controller, API) error) error {
	eg := new(errgroup.Group)
	for i := range controllers {
		i := i
		eg.Go(func() error {
			api, err := j.dial(ctx, &controllers[i], names.ModelTag{})
			if err != nil {
				return err
			}
			defer api.Close()
			return f(&controllers[i], api)
		})
	}
	return eg.Wait()
}

// addAuditLogEntry causes an entry to be added the the audit log.
func (j *JIMM) AddAuditLogEntry(ale *dbmodel.AuditLogEntry) {
	ctx := context.Background()
	redactSensitiveParams(ale)
	if err := j.Database.AddAuditLogEntry(ctx, ale); err != nil {
		zapctx.Error(ctx, "cannot store audit log entry", zap.Error(err), zap.Any("entry", *ale))
	}
}

var sensitiveMethods = map[string]struct{}{
	"login":                 {},
	"logindevice":           {},
	"getdevicesessiontoken": {},
	"loginwithsessiontoken": {},
	"addcredentials":        {},
	"updatecredentials":     {}}
var redactJSON = dbmodel.JSON(`{"params":"redacted"}`)

func redactSensitiveParams(ale *dbmodel.AuditLogEntry) {
	if ale.Params == nil {
		return
	}
	method := strings.ToLower(ale.FacadeMethod)
	if _, ok := sensitiveMethods[method]; ok {
		newRedactMessage := make(dbmodel.JSON, len(redactJSON))
		copy(newRedactMessage, redactJSON)
		ale.Params = newRedactMessage
	}
}

// FindAuditEvents returns audit events matching the given filter.
func (j *JIMM) FindAuditEvents(ctx context.Context, user *openfga.User, filter db.AuditLogFilter) ([]dbmodel.AuditLogEntry, error) {
	const op = errors.Op("jimm.FindAuditEvents")

	access := user.GetAuditLogViewerAccess(ctx, j.ResourceTag())
	if access != ofganames.AuditLogViewerRelation {
		return nil, errors.E(op, errors.CodeUnauthorized, "unauthorized")
	}

	var entries []dbmodel.AuditLogEntry
	err := j.Database.ForEachAuditLogEntry(ctx, filter, func(entry *dbmodel.AuditLogEntry) error {
		entries = append(entries, *entry)
		return nil
	})
	if err != nil {
		return nil, errors.E(op, err)
	}

	return entries, nil
}

// ControllerInfo returns info about a controller connected to JIMM.
func (j *JIMM) ControllerInfo(ctx context.Context, name string) (*dbmodel.Controller, error) {
	const op = errors.Op("jimm.ListControllers")
	ctl := dbmodel.Controller{
		Name: name,
	}
	if err := j.Database.GetController(ctx, &ctl); err != nil {
		return nil, errors.E(op, err)
	}
	return &ctl, nil
}

// ListControllers returns a list of controllers the user has access to.
func (j *JIMM) ListControllers(ctx context.Context, user *openfga.User) ([]dbmodel.Controller, error) {
	const op = errors.Op("jimm.ListControllers")

	if !user.JimmAdmin {
		return nil, errors.E(op, errors.CodeUnauthorized, "unauthorized")
	}

	var controllers []dbmodel.Controller
	err := j.Database.ForEachController(ctx, func(c *dbmodel.Controller) error {
		controllers = append(controllers, *c)
		return nil
	})
	if err != nil {
		return nil, errors.E(op, err)
	}

	return controllers, nil
}

// SetControllerDeprecated records if the controller is to be deprecated.
// No new models or clouds can be added to a deprecated controller.
func (j *JIMM) SetControllerDeprecated(ctx context.Context, user *openfga.User, controllerName string, deprecated bool) error {
	const op = errors.Op("jimm.SetControllerDeprecated")

	if !user.JimmAdmin {
		return errors.E(op, errors.CodeUnauthorized, "unauthorized")
	}

	// Update the local database with the updated cloud definition. We
	// do this in a transaction so that the local view cannot finish in
	// an inconsistent state.
	err := j.Database.Transaction(func(db *db.Database) error {
		c := dbmodel.Controller{
			Name: controllerName,
		}
		if err := db.GetController(ctx, &c); err != nil {
			return err
		}
		c.Deprecated = deprecated
		return db.UpdateController(ctx, &c)
	})
	if err != nil {
		return errors.E(op, err)
	}

	return nil
}

// RemoveController removes a controller.
func (j *JIMM) RemoveController(ctx context.Context, user *openfga.User, controllerName string, force bool) error {
	const op = errors.Op("jimm.RemoveController")

	if !user.JimmAdmin {
		return errors.E(op, errors.CodeUnauthorized, "unauthorized")
	}

	// Update the local database with the updated cloud definition. We
	// do this in a transaction so that the local view cannot finish in
	// an inconsistent state.
	err := j.Database.Transaction(func(db *db.Database) error {
		c := dbmodel.Controller{
			Name: controllerName,
		}
		if err := db.GetController(ctx, &c); err != nil {
			return err
		}

		// if c.UnavailableSince is valid, then we can delete is
		// if c.UnavailableSince is no valid, then we can't delete is
		// if force is true, we can always delete is
		if !(force || c.UnavailableSince.Valid) {
			return errors.E(errors.CodeStillAlive, "controller is still alive")
		}

		models, err := db.GetModelsByController(ctx, c)
		if err != nil {
			return err
		}
		// Delete its models first.
		for _, model := range models {
			err := db.DeleteModel(ctx, &model)
			if err != nil {
				return err
			}
		}

		// Then delete the controller
		return db.DeleteController(ctx, &c)
	})
	if err != nil {
		return errors.E(op, err)
	}

	return nil
}

// FullModelStatus returns the full status of the juju model.
func (j *JIMM) FullModelStatus(ctx context.Context, user *openfga.User, modelTag names.ModelTag, patterns []string) (*jujuparams.FullStatus, error) {
	const op = errors.Op("jimm.RemoveController")

	if !user.JimmAdmin {
		return nil, errors.E(op, errors.CodeUnauthorized, "unauthorized")
	}

	model := dbmodel.Model{
		UUID: sql.NullString{
			String: modelTag.Id(),
			Valid:  true,
		},
	}
	err := j.Database.GetModel(ctx, &model)
	if err != nil {
		return nil, errors.E(op, err)
	}

	api, err := j.dial(ctx, &model.Controller, modelTag)
	if err != nil {
		return nil, errors.E(op, err)
	}

	status, err := api.Status(ctx, patterns)
	if err != nil {
		return nil, errors.E(op, err)
	}

	return status, nil
}

type migrationControllerID = uint

func fillMigrationTarget(db *db.Database, credStore credentials.CredentialStore, controllerName string) (jujuparams.MigrationTargetInfo, migrationControllerID, error) {
	dbController := dbmodel.Controller{
		Name: controllerName,
	}
	ctx := context.Background()
	err := db.GetController(ctx, &dbController)
	if err != nil {
		return jujuparams.MigrationTargetInfo{}, 0, err
	}
	adminUser := dbController.AdminIdentityName
	adminPass := dbController.AdminPassword
	if adminPass == "" {
		u, p, err := credStore.GetControllerCredentials(ctx, controllerName)
		if err != nil {
			return jujuparams.MigrationTargetInfo{}, 0, err
		}
		adminUser = u
		adminPass = p
	}
	if adminUser == "" || adminPass == "" {
		return jujuparams.MigrationTargetInfo{}, 0, errors.E("missing target controller credentials")
	}
	// Should we verify controller can access the cloud where the model is currently hosted?
	apiControllerInfo := dbController.ToAPIControllerInfo()
	targetInfo := jujuparams.MigrationTargetInfo{
		ControllerTag: dbController.ResourceTag().String(),
		Addrs:         apiControllerInfo.APIAddresses,
		CACert:        dbController.CACertificate,
		// The target user must be the admin user as external users don't have username/password credentials.
		AuthTag:  names.NewUserTag(adminUser).String(),
		Password: adminPass,
	}
	return targetInfo, dbController.ID, nil
}

// InitiateInternalMigration initiates a model migration between two controllers within JIMM.
func (j *JIMM) InitiateInternalMigration(ctx context.Context, user *openfga.User, modelNameOrUUID string, targetController string) (jujuparams.InitiateMigrationResult, error) {
	const op = errors.Op("jimm.InitiateInternalMigration")

	migrationTarget, _, err := fillMigrationTarget(j.Database, j.CredentialStore, targetController)
	if err != nil {
		return jujuparams.InitiateMigrationResult{}, errors.E(op, err)
	}

	model := dbmodel.Model{}
	// Check if the user is providing a model UUID or name
	_, err = uuid.Parse(modelNameOrUUID)
	if err != nil {
		s := strings.Split(modelNameOrUUID, "/")
		if len(s) != 2 {
			return jujuparams.InitiateMigrationResult{}, errors.E(op, "invalid model target")
		}

		owner, name := s[0], s[1]
		if !names.IsValidUser(owner) {
			return jujuparams.InitiateMigrationResult{}, errors.E(op, "invalid user name")
		}
		if !names.IsValidModelName(name) {
			return jujuparams.InitiateMigrationResult{}, errors.E(op, "invalid model name")
		}

		model.Name = name
		model.OwnerIdentityName = owner
	} else {
		model.UUID = sql.NullString{
			String: modelNameOrUUID,
			Valid:  true,
		}
	}

	err = j.Database.GetModel(ctx, &model)
	if err != nil {
		return jujuparams.InitiateMigrationResult{}, errors.E(op, err)
	}
	spec := jujuparams.MigrationSpec{ModelTag: model.ResourceTag().String(), TargetInfo: migrationTarget}
	result, err := initiateMigration(ctx, j, user, spec)
	if err != nil {
		return result, errors.E(op, err)
	}
	return result, nil
}
