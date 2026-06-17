// Copyright 2026 Canonical.

// Package params36 converts between the current (Juju 4.x) jujuparams types,
// which identify a model by its qualifier, and the legacy (Juju 3.6) "*Legacy"
// types, which identify a model by its owner tag.
//
// JIMM serves multiple facade versions so that both Juju 3.6 and Juju 4.x
// clients can talk to it directly (see doc and the 3.6-client facade plan).
// Where a facade method's wire format changed between the two majors — almost
// entirely the model owner-tag -> qualifier rename — JIMM's lower-version
// handler speaks the 3.6 wire format using these conversions.
//
// This package is intended to be the ONLY place in JIMM that imports juju's
// "*Legacy" params structs. Those structs are temporary upstream (juju will
// remove them once it stops managing 3.6 controllers); keeping their use
// localised here means a future copy-into-JIMM is a single-file change.
//
// The owner-tag <-> qualifier transform is lossless for qualifiers that name a
// user: a qualifier in user-id form ("alice@external") maps to the owner-tag
// form ("user-alice@external") and back. A qualifier that is not a valid Juju
// user has no faithful owner-tag representation; the response-direction
// converters surface this as an error (single-item) or a per-result error
// (bulk). Handlers serving such models to a 3.6 client decide how to handle
// them — preferring JIMM's own record of the model owner, which for
// JIMM-created models is always a user.
package params36

import (
	"github.com/juju/juju/core/crossmodel"
	jujuparams "github.com/juju/juju/rpc/params"
	"github.com/juju/names/v6"

	"github.com/canonical/jimm/v3/internal/errors"
)

// qualifierToOwnerTag converts a model qualifier in user-id form (e.g.
// "alice@external") into the owner-tag form expected by 3.6 clients (e.g.
// "user-alice@external"). It returns an error for a qualifier that does not
// name a valid Juju user, which therefore has no owner-tag representation.
func qualifierToOwnerTag(qualifier string) (string, error) {
	if !names.IsValidUser(qualifier) {
		return "", errors.Codef(errors.CodeBadRequest, "model qualifier %q is not a user and has no owner-tag representation", qualifier)
	}
	return names.NewUserTag(qualifier).String(), nil
}

// ownerTagToQualifier converts an owner tag sent by a 3.6 client (e.g.
// "user-alice@external") into the qualifier form (e.g. "alice@external") used
// by the current API. It is the inverse of qualifierToOwnerTag for user owners.
func ownerTagToQualifier(ownerTag string) (string, error) {
	ut, err := names.ParseUserTag(ownerTag)
	if err != nil {
		return "", errors.Codef(errors.CodeBadRequest, "%w", err)
	}
	return ut.Id(), nil
}

// toParamsError renders a conversion error as a *jujuparams.Error, preserving
// JIMM's error code where one is set, so it can be returned in a per-result
// error slot.
func toParamsError(err error) *jujuparams.Error {
	return &jujuparams.Error{
		Message: err.Error(),
		Code:    string(errors.ErrorCode(err)),
	}
}

// CurrentModelCreateArgs converts a 3.6 ModelCreateArgsLegacy (owner-tag) into
// the current ModelCreateArgs (qualifier). An empty owner tag yields an empty
// qualifier, mirroring the existing behaviour where the model owner defaults to
// the authenticated user downstream. The legacy form has no TargetController
// field, so it is left unset.
func CurrentModelCreateArgs(in jujuparams.ModelCreateArgsLegacy) (jujuparams.ModelCreateArgs, error) {
	out := jujuparams.ModelCreateArgs{
		Name:               in.Name,
		Config:             in.Config,
		CloudTag:           in.CloudTag,
		CloudRegion:        in.CloudRegion,
		CloudCredentialTag: in.CloudCredentialTag,
	}
	if in.OwnerTag != "" {
		qualifier, err := ownerTagToQualifier(in.OwnerTag)
		if err != nil {
			return jujuparams.ModelCreateArgs{}, err
		}
		out.Qualifier = qualifier
	}
	return out, nil
}

// CurrentOfferFilters converts 3.6 OfferFiltersLegacy (model owner name) into
// the current OfferFilters (model qualifier). It mirrors juju's own
// legacyFiltersToFilters: the model owner name maps directly onto the
// qualifier.
func CurrentOfferFilters(in jujuparams.OfferFiltersLegacy) jujuparams.OfferFilters {
	out := jujuparams.OfferFilters{
		Filters: make([]jujuparams.OfferFilter, len(in.Filters)),
	}
	for i, f := range in.Filters {
		out.Filters[i] = jujuparams.OfferFilter{
			ModelName:              f.ModelName,
			OfferName:              f.OfferName,
			ApplicationName:        f.ApplicationName,
			ApplicationDescription: f.ApplicationDescription,
			ApplicationUser:        f.ApplicationUser,
			Endpoints:              f.Endpoints,
			ConnectedUserTags:      f.ConnectedUserTags,
			AllowedConsumerTags:    f.AllowedConsumerTags,
		}
		if f.OwnerName != "" {
			out.Filters[i].ModelQualifier = f.OwnerName
		}
	}
	return out
}

// TransformOfferURLs rewrites any model-owner segment in the given offer URLs
// into the model-qualifier form used by the current API, mirroring juju's own
// transformOfferURLs. URLs that do not parse, or that carry no qualifier, are
// passed through unchanged so the downstream handler produces the error.
func TransformOfferURLs(in []string) []string {
	out := make([]string, len(in))
	for i, urlStr := range in {
		url, err := crossmodel.ParseOfferURL(urlStr)
		if err != nil || url.ModelQualifier == "" {
			out[i] = urlStr
			continue
		}
		out[i] = url.String()
	}
	return out
}

// LegacyModelInfo converts a current ModelInfo (qualifier) into the 3.6
// ModelInfoLegacy (owner-tag). The JAAS-specific TargetController field has no
// legacy equivalent and is dropped.
func LegacyModelInfo(in jujuparams.ModelInfo) (jujuparams.ModelInfoLegacy, error) {
	ownerTag, err := qualifierToOwnerTag(in.Qualifier)
	if err != nil {
		return jujuparams.ModelInfoLegacy{}, err
	}
	return jujuparams.ModelInfoLegacy{
		Name:                    in.Name,
		Type:                    in.Type,
		UUID:                    in.UUID,
		ControllerUUID:          in.ControllerUUID,
		IsController:            in.IsController,
		ProviderType:            in.ProviderType,
		CloudTag:                in.CloudTag,
		CloudRegion:             in.CloudRegion,
		CloudCredentialTag:      in.CloudCredentialTag,
		CloudCredentialValidity: in.CloudCredentialValidity,
		OwnerTag:                ownerTag,
		Life:                    in.Life,
		Status:                  in.Status,
		Users:                   in.Users,
		Machines:                in.Machines,
		SecretBackends:          in.SecretBackends,
		Migration:               in.Migration,
		AgentVersion:            in.AgentVersion,
		SupportedFeatures:       in.SupportedFeatures,
	}, nil
}

// LegacyModelInfoResults converts a bulk ModelInfoResults into its legacy form.
// A result whose qualifier has no owner-tag representation is converted into a
// result-level error rather than failing the whole batch.
func LegacyModelInfoResults(in jujuparams.ModelInfoResults) jujuparams.ModelInfoResultsLegacy {
	out := jujuparams.ModelInfoResultsLegacy{
		Results: make([]jujuparams.ModelInfoResultLegacy, len(in.Results)),
	}
	for i, r := range in.Results {
		if r.Result == nil {
			out.Results[i] = jujuparams.ModelInfoResultLegacy{Error: r.Error}
			continue
		}
		mi, err := LegacyModelInfo(*r.Result)
		if err != nil {
			out.Results[i] = jujuparams.ModelInfoResultLegacy{Error: toParamsError(err)}
			continue
		}
		out.Results[i] = jujuparams.ModelInfoResultLegacy{Result: &mi}
	}
	return out
}

// legacyModel converts a current Model (qualifier) into the 3.6 ModelLegacy
// (owner-tag).
func legacyModel(in jujuparams.Model) (jujuparams.ModelLegacy, error) {
	ownerTag, err := qualifierToOwnerTag(in.Qualifier)
	if err != nil {
		return jujuparams.ModelLegacy{}, err
	}
	return jujuparams.ModelLegacy{
		Name:     in.Name,
		UUID:     in.UUID,
		Type:     in.Type,
		OwnerTag: ownerTag,
	}, nil
}

// LegacyUserModelList converts a current UserModelList (qualifier) into the 3.6
// UserModelListLegacy (owner-tag). UserModel has no per-item error slot, so a
// model whose qualifier has no owner-tag representation fails the whole
// conversion; callers should ensure model owners are users (they are for
// JIMM-created models) or pre-filter.
func LegacyUserModelList(in jujuparams.UserModelList) (jujuparams.UserModelListLegacy, error) {
	out := jujuparams.UserModelListLegacy{
		UserModels: make([]jujuparams.UserModelLegacy, len(in.UserModels)),
	}
	for i, um := range in.UserModels {
		ml, err := legacyModel(um.Model)
		if err != nil {
			return jujuparams.UserModelListLegacy{}, err
		}
		out.UserModels[i] = jujuparams.UserModelLegacy{
			ModelLegacy:    ml,
			LastConnection: um.LastConnection,
		}
	}
	return out, nil
}

// legacyModelStatus converts a single current ModelStatus into its legacy form.
// A ModelStatus that already carries an error is passed through unchanged; a
// qualifier with no owner-tag representation is recorded as the item's error.
func legacyModelStatus(in jujuparams.ModelStatus) jujuparams.ModelStatusLegacy {
	out := jujuparams.ModelStatusLegacy{
		ModelTag:           in.ModelTag,
		Life:               in.Life,
		Type:               in.Type,
		HostedMachineCount: in.HostedMachineCount,
		ApplicationCount:   in.ApplicationCount,
		UnitCount:          in.UnitCount,
		Applications:       in.Applications,
		Machines:           in.Machines,
		Volumes:            in.Volumes,
		Filesystems:        in.Filesystems,
		Error:              in.Error,
	}
	if in.Error != nil {
		return out
	}
	ownerTag, err := qualifierToOwnerTag(in.Qualifier)
	if err != nil {
		out.Error = toParamsError(err)
		return out
	}
	out.OwnerTag = ownerTag
	return out
}

// LegacyModelStatusResults converts a bulk ModelStatusResults into its legacy
// form, recording any per-model conversion failure in that model's error.
func LegacyModelStatusResults(in jujuparams.ModelStatusResults) jujuparams.ModelStatusResultsLegacy {
	out := jujuparams.ModelStatusResultsLegacy{
		Results: make([]jujuparams.ModelStatusLegacy, len(in.Results)),
	}
	for i, ms := range in.Results {
		out.Results[i] = legacyModelStatus(ms)
	}
	return out
}

// legacyModelSummary converts a single current ModelSummary into its legacy
// form.
func legacyModelSummary(in jujuparams.ModelSummary) (jujuparams.ModelSummaryLegacy, error) {
	ownerTag, err := qualifierToOwnerTag(in.Qualifier)
	if err != nil {
		return jujuparams.ModelSummaryLegacy{}, err
	}
	return jujuparams.ModelSummaryLegacy{
		Name:               in.Name,
		UUID:               in.UUID,
		Type:               in.Type,
		ControllerUUID:     in.ControllerUUID,
		IsController:       in.IsController,
		ProviderType:       in.ProviderType,
		CloudTag:           in.CloudTag,
		CloudRegion:        in.CloudRegion,
		CloudCredentialTag: in.CloudCredentialTag,
		OwnerTag:           ownerTag,
		Life:               in.Life,
		Status:             in.Status,
		UserAccess:         in.UserAccess,
		UserLastConnection: in.UserLastConnection,
		Counts:             in.Counts,
		Migration:          in.Migration,
		AgentVersion:       in.AgentVersion,
	}, nil
}

// LegacyModelSummaryResults converts a bulk ModelSummaryResults into its legacy
// form. A result whose qualifier has no owner-tag representation is converted
// into a result-level error rather than failing the whole batch.
func LegacyModelSummaryResults(in jujuparams.ModelSummaryResults) jujuparams.ModelSummaryResultsLegacy {
	out := jujuparams.ModelSummaryResultsLegacy{
		Results: make([]jujuparams.ModelSummaryResultLegacy, len(in.Results)),
	}
	for i, r := range in.Results {
		if r.Result == nil {
			out.Results[i] = jujuparams.ModelSummaryResultLegacy{Error: r.Error}
			continue
		}
		ms, err := legacyModelSummary(*r.Result)
		if err != nil {
			out.Results[i] = jujuparams.ModelSummaryResultLegacy{Error: toParamsError(err)}
			continue
		}
		out.Results[i] = jujuparams.ModelSummaryResultLegacy{Result: &ms}
	}
	return out
}
