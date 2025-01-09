// Copyright 2024 Canonical.

package jimm

import (
	"context"
	"database/sql"
	stderrors "errors"
	"fmt"
	"strings"
	"sync"

	"github.com/go-macaroon-bakery/macaroon-bakery/v3/bakery"
	"github.com/juju/juju/core/crossmodel"
	jujuparams "github.com/juju/juju/rpc/params"
	"github.com/juju/names/v5"
	"github.com/juju/zaputil"
	"github.com/juju/zaputil/zapctx"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/canonical/jimm/v3/internal/db"
	"github.com/canonical/jimm/v3/internal/dbmodel"
	"github.com/canonical/jimm/v3/internal/errors"
	"github.com/canonical/jimm/v3/internal/jimm/permissions"
	"github.com/canonical/jimm/v3/internal/openfga"
	ofganames "github.com/canonical/jimm/v3/internal/openfga/names"
)

// AddApplicationOfferParams holds parameters for the Offer method.
type AddApplicationOfferParams struct {
	ModelTag               names.ModelTag
	OwnerTag               names.UserTag
	OfferName              string
	ApplicationName        string
	ApplicationDescription string
	Endpoints              map[string]string
}

// Offer creates a new application offer.
func (j *JIMM) Offer(ctx context.Context, user *openfga.User, offer AddApplicationOfferParams) error {
	const op = errors.Op("jimm.Offer")

	model := dbmodel.Model{
		UUID: sql.NullString{
			String: offer.ModelTag.Id(),
			Valid:  true,
		},
	}
	if err := j.Database.GetModel(ctx, &model); err != nil {
		if errors.ErrorCode(err) == errors.CodeNotFound {
			return errors.E(op, err, "model not found")
		}
		return errors.E(op, err)
	}

	isAdmin, err := openfga.IsAdministrator(ctx, user, model.ResourceTag())
	if err != nil {
		zapctx.Error(ctx, "failed administraor check", zap.Error(err))
		return errors.E(op, "failed administrator check", err)
	}
	if !isAdmin {
		return errors.E(op, errors.CodeUnauthorized, "unauthorized")
	}

	offerURL := crossmodel.OfferURL{
		User:      model.OwnerIdentityName,
		ModelName: model.Name,
		// Confusingly the application name in the offer URL is
		// actually the offer name.
		ApplicationName: offer.OfferName,
	}

	// Verify offer URL doesn't already exist.
	var offerCheck dbmodel.ApplicationOffer
	offerCheck.URL = offerURL.String()
	err = j.Database.GetApplicationOffer(ctx, &offerCheck)
	if err == nil {
		return errors.E(fmt.Sprintf("offer %s already exists, please use a different name", offerURL.String()), errors.CodeAlreadyExists)
	} else if errors.ErrorCode(err) != errors.CodeNotFound {
		// Anything besides Not Found is a problem.
		return errors.E(op, err)
	}

	api, err := j.dial(ctx, &model.Controller, names.ModelTag{})
	if err != nil {
		return errors.E(op, err)
	}
	defer api.Close()

	ownerTag := offer.OwnerTag.String()
	if ownerTag == "" {
		ownerTag = user.Tag().String()
	}
	err = api.Offer(ctx,
		offerURL,
		jujuparams.AddApplicationOffer{
			ModelTag:               offer.ModelTag.String(),
			OwnerTag:               ownerTag,
			OfferName:              offer.OfferName,
			ApplicationName:        offer.ApplicationName,
			ApplicationDescription: offer.ApplicationDescription,
			Endpoints:              offer.Endpoints,
		})
	if err != nil {
		if strings.Contains(err.Error(), "application offer already exists") {
			return errors.E(op, err, errors.CodeAlreadyExists)
		}
		return errors.E(op, err)
	}

	offerDetails := jujuparams.ApplicationOfferAdminDetailsV5{
		ApplicationOfferDetailsV5: jujuparams.ApplicationOfferDetailsV5{
			OfferURL: offerURL.String(),
		},
	}
	err = api.GetApplicationOffer(ctx, &offerDetails)
	if err != nil {
		zapctx.Error(ctx, "failed to fetch details of the created application offer", zaputil.Error(err))
		return errors.E(op, err)
	}

	doc := dbmodel.ApplicationOffer{
		ModelID: model.ID,
		Name:    offerDetails.OfferName,
		UUID:    offerDetails.OfferUUID,
		URL:     offerDetails.OfferURL,
	}
	err = j.Database.Transaction(func(db *db.Database) error {
		if err := db.AddApplicationOffer(ctx, &doc); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		zapctx.Error(ctx, "failed to store the created application offer", zaputil.Error(err))
		return errors.E(op, err)
	}

	if err := j.OpenFGAClient.AddModelApplicationOffer(
		ctx,
		model.ResourceTag(),
		doc.ResourceTag(),
	); err != nil {
		zapctx.Error(
			ctx,
			"failed to add relation between model and application offer",
			zap.String("model", model.UUID.String),
			zap.String("application-offer", doc.UUID))
	}

	ownerId := offer.OwnerTag.Id()
	if ownerId == "" {
		ownerId = user.Tag().Id()
	}

	identity, err := dbmodel.NewIdentity(ownerId)
	if err != nil {
		return errors.E(op, err)
	}

	owner := openfga.NewUser(
		identity,
		j.OpenFGAClient,
	)
	if err := owner.SetApplicationOfferAccess(ctx, doc.ResourceTag(), ofganames.AdministratorRelation); err != nil {
		zapctx.Error(
			ctx,
			"failed relation between user and application offer",
			zap.String("user", ownerId),
			zap.String("application-offer", doc.UUID))
	}

	if err := j.everyoneUser().SetApplicationOfferAccess(ctx, doc.ResourceTag(), ofganames.ReaderRelation); err != nil {
		zapctx.Error(
			ctx,
			"failed relation between user and application offer",
			zap.String("user", ownerId),
			zap.String("application-offer", doc.UUID))
	}

	return nil
}

// GetApplicationOfferConsumeDetails consume the application offer
// specified by details.ApplicationOfferDetails.OfferURL and completes
// the rest of the details.
func (j *JIMM) GetApplicationOfferConsumeDetails(ctx context.Context, user *openfga.User, details *jujuparams.ConsumeOfferDetails, v bakery.Version) error {
	const op = errors.Op("jimm.GetApplicationOfferConsumeDetails")

	offer := dbmodel.ApplicationOffer{
		URL: details.Offer.OfferURL,
	}
	if err := j.Database.GetApplicationOffer(ctx, &offer); err != nil {
		if errors.ErrorCode(err) == errors.CodeNotFound {
			return errors.E(op, err, "application offer not found")
		}
		return errors.E(op, err)
	}

	accessLevel, err := j.getUserOfferAccess(ctx, user, offer.ResourceTag())
	if err != nil {
		return errors.E(op, err)
	}

	switch accessLevel {
	case string(jujuparams.OfferAdminAccess):
	case string(jujuparams.OfferConsumeAccess):
	case string(jujuparams.OfferReadAccess):
		return errors.E(op, errors.CodeUnauthorized, "unauthorized")
	default:
		// TODO (ashipika)
		//   - think about the returned error code
		return errors.E(op, errors.CodeNotFound)
	}

	api, err := j.dial(
		ctx,
		&offer.Model.Controller,
		names.ModelTag{},
		permission{
			resource: names.NewApplicationOfferTag(offer.UUID).String(),
			relation: accessLevel,
		},
	)
	if err != nil {
		return errors.E(op, err)
	}
	defer api.Close()

	if err := api.GetApplicationOfferConsumeDetails(ctx, user.ResourceTag(), details, v); err != nil {
		return errors.E(op, err)
	}

	// Fix the consume details from the controller to be correct for JAAS.
	// Filter out any juju local users.
	users, err := j.listApplicationOfferUsers(ctx, offer.ResourceTag(), user.Identity, accessLevel == string(jujuparams.OfferAdminAccess))
	if err != nil {
		return errors.E(op, err)
	}
	details.Offer.Users = users

	ci := details.ControllerInfo
	// Fix the addresses to be a controller's external addresses.
	details.ControllerInfo = &jujuparams.ExternalControllerInfo{
		ControllerTag: offer.Model.Controller.Tag().String(),
		Alias:         offer.Model.Controller.Name,
	}
	if offer.Model.Controller.PublicAddress != "" {
		details.ControllerInfo.Addrs = []string{offer.Model.Controller.PublicAddress}
	} else {
		details.ControllerInfo.Addrs = ci.Addrs
		details.ControllerInfo.CACert = ci.CACert
	}

	return nil
}

// listApplicationOfferUsers filters the application offer user list
// to be suitable for the given user at the given access level. All juju-
// local users are omitted, and if the user is not an admin then they can
// only see themselves.
// TODO(Kian) CSS-6040 Consider changing wherever this function is used to
// better encapsulate transforming Postgres/OpenFGA objects into Juju objects.
func (j *JIMM) listApplicationOfferUsers(ctx context.Context, offer names.ApplicationOfferTag, user *dbmodel.Identity, adminAccess bool) ([]jujuparams.OfferUserDetails, error) {
	users := make(map[string]string)
	// we loop through relations in a decreasing order of access
	for _, relation := range []openfga.Relation{
		ofganames.AdministratorRelation,
		ofganames.ConsumerRelation,
		ofganames.ReaderRelation,
	} {
		usersWithRelation, err := openfga.ListUsersWithAccess(ctx, j.OpenFGAClient, offer, relation)
		if err != nil {
			return nil, errors.E(err)
		}
		for _, user := range usersWithRelation {
			// if the user is in the users map, it must already have a higher
			// access level - we skip this user
			if users[user.Name] != "" {
				continue
			}
			users[user.Name] = permissions.ToOfferAccessString(relation)
		}
	}

	userDetails := []jujuparams.OfferUserDetails{}
	for username, level := range users {
		// non-admin users should only see their own access level
		// and the access level of "everyone" - meaning the access
		// level everybody has.
		if !adminAccess && username != ofganames.EveryoneUser && username != user.Name {
			continue
		}
		userDetails = append(userDetails, jujuparams.OfferUserDetails{
			UserName: username,
			Access:   level,
		})
	}
	return userDetails, nil
}

var noApplicationOfferAccessError = errors.E("no application offer access")

// enrichOfferDetails replaces fields on an application offer's details with information
// where JIMM is authoritative. It returns a noApplicationOfferAccessError if the user
// does not have access to the offer.
func (j *JIMM) enrichOfferDetails(ctx context.Context, user *openfga.User, offerDetail jujuparams.ApplicationOfferAdminDetailsV5) (jujuparams.ApplicationOfferAdminDetailsV5, error) {
	// TODO (alesstimec) Optimize this: currently check all possible
	// permission levels for an offer, this is suboptimal.
	offerTag := names.NewApplicationOfferTag(offerDetail.OfferUUID)
	accessLevel, err := j.getUserOfferAccess(ctx, user, offerTag)
	if err != nil {
		return offerDetail, err
	}

	if accessLevel == "" {
		return jujuparams.ApplicationOfferAdminDetailsV5{}, noApplicationOfferAccessError
	}

	// non-admin users should not see connections of an application
	// offer.
	if accessLevel != "admin" {
		offerDetail.Connections = nil
	}
	users, err := j.listApplicationOfferUsers(ctx, offerTag, user.Identity, accessLevel == "admin")
	if err != nil {
		return offerDetail, err
	}

	offerDetail.Users = users

	return offerDetail, nil
}

// GetApplicationOffer returns details of the offer with the specified URL.
func (j *JIMM) GetApplicationOffer(ctx context.Context, user *openfga.User, offerURL string) (*jujuparams.ApplicationOfferAdminDetailsV5, error) {
	const op = errors.Op("jimm.GetApplicationOffer")

	offer := dbmodel.ApplicationOffer{
		URL: offerURL,
	}
	err := j.Database.GetApplicationOffer(ctx, &offer)
	if err != nil {
		if errors.ErrorCode(err) == errors.CodeNotFound {
			return nil, errors.E(op, err, "application offer not found")
		}
		return nil, errors.E(op, err)
	}

	accessLevel, err := j.getUserOfferAccess(ctx, user, offer.ResourceTag())
	if err != nil {
		return nil, errors.E(op, err)
	}

	// if this user does not have access to this application offer
	// we return a not found error.
	if accessLevel == "" {
		return nil, errors.E(op, errors.CodeNotFound, "application offer not found")
	}

	// Always collect application-offer admin details from the
	// controller. The all-watcher events do not include enough
	// information to reasonably keep the local database up-to-date,
	// and it would be non-trivial to make it do so.
	api, err := j.dial(
		ctx,
		&offer.Model.Controller,
		names.ModelTag{},
		permission{
			resource: names.NewApplicationOfferTag(offer.UUID).String(),
			relation: accessLevel,
		},
	)
	if err != nil {
		return nil, errors.E(op, err)
	}
	defer api.Close()

	var offerDetails jujuparams.ApplicationOfferAdminDetailsV5
	offerDetails.OfferURL = offerURL
	if err := api.GetApplicationOffer(ctx, &offerDetails); err != nil {
		return nil, errors.E(op, err)
	}

	offerDetails, err = j.enrichOfferDetails(ctx, user, offerDetails)
	if err != nil {
		return nil, errors.E(op, err)
	}

	return &offerDetails, nil
}

// DestroyOffer removes the application offer.
func (j *JIMM) DestroyOffer(ctx context.Context, user *openfga.User, offerURL string, force bool) error {
	const op = errors.Op("jimm.DestroyOffer")

	err := j.doApplicationOfferAdmin(ctx, user, offerURL, func(offer *dbmodel.ApplicationOffer, api API) error {
		if err := api.DestroyApplicationOffer(ctx, offerURL, force); err != nil {
			return err
		}
		if err := j.Database.DeleteApplicationOffer(ctx, offer); err != nil {
			return err
		}
		if err := j.OpenFGAClient.RemoveApplicationOffer(
			ctx,
			offer.ResourceTag(),
		); err != nil {
			zapctx.Error(
				ctx,
				"cannot remove application offer",
				zap.String("application-offer", offer.UUID))
		}

		return nil
	})
	if err != nil {
		return errors.E(op, err)
	}

	return nil
}

// getUserOfferAccess returns the access level string for the user to the
// application offer. It returns the highest access level the user is granted.
func (j *JIMM) getUserOfferAccess(ctx context.Context, user *openfga.User, offerTag names.ApplicationOfferTag) (string, error) {
	isOfferAdmin, err := openfga.IsAdministrator(ctx, user, offerTag)
	if err != nil {
		zapctx.Error(ctx, "openfga check failed", zap.Error(err))
		return "", errors.E(err)
	}
	if isOfferAdmin {
		return string(jujuparams.OfferAdminAccess), nil
	}
	isOfferConsumer, err := user.IsApplicationOfferConsumer(ctx, offerTag)
	if err != nil {
		zapctx.Error(ctx, "openfga check failed", zap.Error(err))
		return "", errors.E(err)
	}
	if isOfferConsumer {
		return string(jujuparams.OfferConsumeAccess), nil
	}
	isOfferReader, err := user.IsApplicationOfferReader(ctx, offerTag)
	if err != nil {
		zapctx.Error(ctx, "openfga check failed", zap.Error(err))
		return "", errors.E(err)
	}
	if isOfferReader {
		return string(jujuparams.OfferReadAccess), nil
	}
	return "", nil
}

type offers struct {
	mu     sync.Mutex
	offers []jujuparams.ApplicationOfferAdminDetailsV5
}

func (o *offers) addOffer(offer jujuparams.ApplicationOfferAdminDetailsV5) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.offers = append(o.offers, offer)
}

// FindApplicationOffers returns details of offers matching the specified filter.
func (j *JIMM) FindApplicationOffers(ctx context.Context, user *openfga.User, filters ...jujuparams.OfferFilter) ([]jujuparams.ApplicationOfferAdminDetailsV5, error) {
	const op = errors.Op("jimm.FindApplicationOffers")

	if len(filters) == 0 {
		return nil, errors.E(op, errors.CodeBadRequest, "at least one filter must be specified")
	}

	controllers := make(map[uint]*dbmodel.Controller)
	err := j.Database.ForEachController(ctx, func(ctl *dbmodel.Controller) error {
		controllers[ctl.ID] = ctl
		return nil
	})
	if err != nil {
		return nil, errors.E(op, err)
	}

	offers, err := j.queryControllersForOffers(ctx, user, controllers, func(api API) ([]jujuparams.ApplicationOfferAdminDetailsV5, error) {
		return api.FindApplicationOffers(ctx, filters)
	})
	if err != nil {
		return nil, errors.E(op, err)
	}
	return offers, nil
}

// ListApplicationOffers returns details of offers matching the specified filter.
func (j *JIMM) ListApplicationOffers(ctx context.Context, user *openfga.User, filters ...jujuparams.OfferFilter) ([]jujuparams.ApplicationOfferAdminDetailsV5, error) {
	const op = errors.Op("jimm.ListApplicationOffers")

	if len(filters) == 0 {
		return nil, errors.E(op, errors.CodeBadRequest, "at least one filter must be specified")
	}

	controllers := make(map[uint]*dbmodel.Controller)
	for _, f := range filters {
		if f.ModelName == "" {
			return nil, errors.E(op, "application offer filter must specify a model name")
		}
		if f.OwnerName == "" {
			f.OwnerName = user.Name
		}

		m := dbmodel.Model{
			Name:              f.ModelName,
			OwnerIdentityName: f.OwnerName,
		}
		if err := j.Database.GetModel(ctx, &m); err != nil {
			return nil, errors.E(op, err)
		}
		controllers[m.Controller.ID] = &m.Controller
	}

	offers, err := j.queryControllersForOffers(ctx, user, controllers, func(api API) ([]jujuparams.ApplicationOfferAdminDetailsV5, error) {
		return api.ListApplicationOffers(ctx, filters)
	})
	if err != nil {
		return nil, errors.E(op, err)
	}
	return offers, nil
}

func (j *JIMM) queryControllersForOffers(ctx context.Context, user *openfga.User, controllers map[uint]*dbmodel.Controller, query func(API) ([]jujuparams.ApplicationOfferAdminDetailsV5, error)) ([]jujuparams.ApplicationOfferAdminDetailsV5, error) {
	var offerDetails offers
	eg, ctx := errgroup.WithContext(ctx)

	for _, ctl := range controllers {
		eg.Go(func() error {
			api, err := j.dial(ctx, ctl, names.ModelTag{})
			if err != nil {
				return errors.E(err)
			}
			defer api.Close()
			controllerOffers, err := query(api)
			if err != nil {
				return errors.E(err)
			}
			for _, offer := range controllerOffers {
				offer, err = j.enrichOfferDetails(ctx, user, offer)
				if err != nil {
					if stderrors.Is(err, noApplicationOfferAccessError) {
						continue
					}
					return errors.E(err)
				}

				offerDetails.addOffer(offer)
			}
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return offerDetails.offers, err
	}

	return offerDetails.offers, nil
}

// doApplicationOfferAdmin performs the given function on an application offer
// only if the given user has admin access on the model of the offer, or is a
// controller superuser. Otherwise an unauthorized error is returned.
//
// Note: The user does not need to have any access level on the offer itself.
// As long as they are model admins or controller superusers they can also
// manipulate the application offer as admins.
func (j *JIMM) doApplicationOfferAdmin(ctx context.Context, user *openfga.User, offerURL string, f func(offer *dbmodel.ApplicationOffer, api API) error) error {
	const op = errors.Op("jimm.doApplicationOfferAdmin")

	offer := dbmodel.ApplicationOffer{
		URL: offerURL,
	}
	if err := j.Database.GetApplicationOffer(ctx, &offer); err != nil {
		return errors.E(op, err)
	}

	isOfferAdmin, err := openfga.IsAdministrator(ctx, user, offer.ResourceTag())
	if err != nil {
		return errors.E(op, err)
	}
	if !isOfferAdmin {
		return errors.E(op, errors.CodeUnauthorized, "unauthorized")
	}
	// add offer admin claim
	api, err := j.dial(
		ctx,
		&offer.Model.Controller,
		names.ModelTag{},
		permission{
			resource: names.NewApplicationOfferTag(offer.UUID).String(),
			relation: string(jujuparams.OfferAdminAccess),
		},
	)
	if err != nil {
		return errors.E(op, err)
	}
	defer api.Close()
	if err := f(&offer, api); err != nil {
		return errors.E(op, err)
	}
	return nil
}
