// Copyright 2025 Canonical.

package rebac_admin

import (
	"context"
	"fmt"

	v1 "github.com/canonical/rebac-admin-ui-handlers/v1"
	"github.com/canonical/rebac-admin-ui-handlers/v1/resources"
	"github.com/juju/names/v5"
	"github.com/juju/zaputil/zapctx"
	"go.uber.org/zap"

	"github.com/canonical/jimm/v3/internal/common/pagination"
	"github.com/canonical/jimm/v3/internal/errors"
	"github.com/canonical/jimm/v3/internal/jimmhttp/rebac_admin/utils"
	"github.com/canonical/jimm/v3/internal/jujuapi"
	"github.com/canonical/jimm/v3/internal/openfga"
	ofganames "github.com/canonical/jimm/v3/internal/openfga/names"
	apiparams "github.com/canonical/jimm/v3/pkg/api/params"
	jimmnames "github.com/canonical/jimm/v3/pkg/names"
)

type identitiesService struct {
	jimm jujuapi.JIMM
}

func newidentitiesService(jimm jujuapi.JIMM) *identitiesService {
	return &identitiesService{
		jimm: jimm,
	}
}

// ListIdentities returns a page of Identity objects of at least `size` elements if available.
func (s *identitiesService) ListIdentities(ctx context.Context, params *resources.GetIdentitiesParams) (*resources.PaginatedResponse[resources.Identity], error) {
	user, err := utils.GetUserFromContext(ctx)
	if err != nil {
		return nil, err
	}

	count, err := s.jimm.IdentityManager().CountIdentities(ctx, user)
	if err != nil {
		return nil, err
	}
	page, nextPage, pagination := pagination.CreatePagination(params.Size, params.Page, count)
	match := ""
	if params.Filter != nil && *params.Filter != "" {
		match = *params.Filter
	}
	users, err := s.jimm.IdentityManager().ListIdentities(ctx, user, pagination, match)
	if err != nil {
		return nil, err
	}
	rIdentities := make([]resources.Identity, len(users))
	for i, u := range users {
		rIdentities[i] = utils.FromUserToIdentity(u)
	}

	return &resources.PaginatedResponse[resources.Identity]{
		Data: rIdentities,
		Meta: resources.ResponseMeta{
			Page:  &page,
			Size:  len(rIdentities),
			Total: &count,
		},
		Next: resources.Next{
			Page: nextPage,
		},
	}, nil
}

// CreateIdentity creates a single Identity.
func (s *identitiesService) CreateIdentity(ctx context.Context, identity *resources.Identity) (*resources.Identity, error) {
	return nil, v1.NewNotImplementedError("create identity not implemented")
}

// GetIdentity returns a single Identity.
func (s *identitiesService) GetIdentity(ctx context.Context, identityId string) (*resources.Identity, error) {
	user, err := s.jimm.IdentityManager().FetchIdentity(ctx, identityId)
	if err != nil {
		if errors.ErrorCode(err) == errors.CodeNotFound {
			return nil, v1.NewNotFoundError(fmt.Sprintf("User with id %s not found", identityId))
		}
		return nil, err
	}
	identity := utils.FromUserToIdentity(*user)
	return &identity, nil
}

// UpdateIdentity updates an Identity.
func (s *identitiesService) UpdateIdentity(ctx context.Context, identity *resources.Identity) (*resources.Identity, error) {
	return nil, v1.NewNotImplementedError("update identity not implemented")
}

// DeleteIdentity deletes an Identity.
func (s *identitiesService) DeleteIdentity(ctx context.Context, identityId string) (bool, error) {
	return false, v1.NewNotImplementedError("delete identity not implemented")
}

// GetIdentityRoles returns a page of identities in a Role identified by `roleId`.
func (s *identitiesService) GetIdentityRoles(ctx context.Context, identityId string, params *resources.GetIdentitiesItemRolesParams) (*resources.PaginatedResponse[resources.Role], error) {
	user, err := utils.GetUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	objUser, err := s.jimm.IdentityManager().FetchIdentity(ctx, identityId)
	if err != nil {
		return nil, v1.NewNotFoundError(fmt.Sprintf("User with id %s not found", identityId))
	}
	filter := utils.CreateTokenPaginationFilter(params.Size, params.NextToken, params.NextPageToken)
	tuples, cNextToken, err := s.jimm.PermissionManager().ListRelationshipTuples(ctx, user, apiparams.RelationshipTuple{
		Object:       objUser.ResourceTag().String(),
		Relation:     ofganames.AssigneeRelation.String(),
		TargetObject: openfga.RoleType.String(),
	}, int32(filter.Limit()), filter.Token()) // #nosec G115 accept integer conversion
	if err != nil {
		return nil, err
	}

	roles := make([]resources.Role, 0, len(tuples))
	for _, t := range tuples {
		dbRole, err := s.jimm.RoleManager().GetRoleByUUID(ctx, user, t.Target.ID)
		if err != nil {
			// Handle the case where the role was removed from the DB but a lingering OpenFGA tuple still exists.
			// Don't return an error as that would prevent a user from viewing their groups, instead drop the role from the result.
			if errors.ErrorCode(err) == errors.CodeNotFound {
				continue
			}
			return nil, err
		}
		roles = append(roles, resources.Role{
			Id:   &t.Target.ID,
			Name: dbRole.Name,
		})
	}

	originalToken := filter.Token()
	res := resources.PaginatedResponse[resources.Role]{
		Data: roles,
		Meta: resources.ResponseMeta{
			Size:      len(roles),
			PageToken: &originalToken,
		},
	}
	if cNextToken != "" {
		res.Next.PageToken = &cNextToken
	}
	return &res, nil
}

// PatchRoleIdentities performs addition or removal of identities to/from a Role identified by `roleId`.
func (s *identitiesService) PatchIdentityRoles(ctx context.Context, identityId string, rolePatches []resources.IdentityRolesPatchItem) (bool, error) {
	user, err := utils.GetUserFromContext(ctx)
	if err != nil {
		return false, err
	}

	objUser, err := s.jimm.IdentityManager().FetchIdentity(ctx, identityId)
	if err != nil {
		return false, v1.NewNotFoundError(fmt.Sprintf("User with id %s not found", identityId))
	}
	additions := make([]apiparams.RelationshipTuple, 0)
	deletions := make([]apiparams.RelationshipTuple, 0)
	for _, p := range rolePatches {
		if !jimmnames.IsValidRoleId(p.Role) {
			return false, v1.NewValidationError(fmt.Sprintf("ID %s is not a valid role ID", p.Role))
		}
		t := apiparams.RelationshipTuple{
			Object:       objUser.ResourceTag().String(),
			Relation:     ofganames.AssigneeRelation.String(),
			TargetObject: jimmnames.NewRoleTag(p.Role).String(),
		}
		if p.Op == resources.IdentityRolesPatchItemOpAdd {
			additions = append(additions, t)
		} else if p.Op == "remove" {
			deletions = append(deletions, t)
		}
	}
	if len(additions) > 0 {
		err = s.jimm.PermissionManager().AddRelation(ctx, user, additions)
		if err != nil {
			zapctx.Error(context.Background(), "cannot add relations", zap.Error(err))
			return false, v1.NewUnknownError(err.Error())
		}
	}
	if len(deletions) > 0 {
		err = s.jimm.PermissionManager().RemoveRelation(ctx, user, deletions)
		if err != nil {
			zapctx.Error(context.Background(), "cannot remove relations", zap.Error(err))
			return false, v1.NewUnknownError(err.Error())
		}
	}
	return true, nil
}

// GetIdentityGroups returns a page of Groups for identity `identityId`.
func (s *identitiesService) GetIdentityGroups(ctx context.Context, identityId string, params *resources.GetIdentitiesItemGroupsParams) (*resources.PaginatedResponse[resources.Group], error) {
	user, err := utils.GetUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	objUser, err := s.jimm.IdentityManager().FetchIdentity(ctx, identityId)
	if err != nil {
		return nil, v1.NewNotFoundError(fmt.Sprintf("User with id %s not found", identityId))
	}
	filter := utils.CreateTokenPaginationFilter(params.Size, params.NextToken, params.NextPageToken)
	tuples, cNextToken, err := s.jimm.PermissionManager().ListRelationshipTuples(ctx, user, apiparams.RelationshipTuple{
		Object:       objUser.ResourceTag().String(),
		Relation:     ofganames.MemberRelation.String(),
		TargetObject: openfga.GroupType.String(),
	}, int32(filter.Limit()), filter.Token()) // #nosec G115 accept integer conversion
	if err != nil {
		return nil, err
	}

	groups := make([]resources.Group, 0, len(tuples))
	for _, t := range tuples {
		dbGroup, err := s.jimm.GroupManager().GetGroupByUUID(ctx, user, t.Target.ID)
		if err != nil {
			// Handle the case where the group was removed from the DB but a lingering OpenFGA tuple still exists.
			// Don't return an error as that would prevent a user from viewing their groups, instead drop the group from the result.
			if errors.ErrorCode(err) == errors.CodeNotFound {
				continue
			}
			return nil, err
		}
		groups = append(groups, resources.Group{
			Id:   &t.Target.ID,
			Name: dbGroup.Name,
		})
	}

	originalToken := filter.Token()
	res := resources.PaginatedResponse[resources.Group]{
		Data: groups,
		Meta: resources.ResponseMeta{
			Size:      len(groups),
			PageToken: &originalToken,
		},
	}
	if cNextToken != "" {
		res.Next.PageToken = &cNextToken
	}
	return &res, nil
}

// PatchIdentityGroups performs addition or removal of a Group to/from an Identity.
func (s *identitiesService) PatchIdentityGroups(ctx context.Context, identityId string, groupPatches []resources.IdentityGroupsPatchItem) (bool, error) {
	user, err := utils.GetUserFromContext(ctx)
	if err != nil {
		return false, err
	}

	objUser, err := s.jimm.IdentityManager().FetchIdentity(ctx, identityId)
	if err != nil {
		return false, v1.NewNotFoundError(fmt.Sprintf("User with id %s not found", identityId))
	}
	additions := make([]apiparams.RelationshipTuple, 0)
	deletions := make([]apiparams.RelationshipTuple, 0)
	for _, p := range groupPatches {
		if !jimmnames.IsValidGroupId(p.Group) {
			return false, v1.NewValidationError(fmt.Sprintf("ID %s is not a valid group ID", p.Group))
		}
		t := apiparams.RelationshipTuple{
			Object:       objUser.ResourceTag().String(),
			Relation:     ofganames.MemberRelation.String(),
			TargetObject: jimmnames.NewGroupTag(p.Group).String(),
		}
		if p.Op == "add" {
			additions = append(additions, t)
		} else if p.Op == "remove" {
			deletions = append(deletions, t)
		}
	}
	if len(additions) > 0 {
		err = s.jimm.PermissionManager().AddRelation(ctx, user, additions)
		if err != nil {
			zapctx.Error(context.Background(), "cannot add relations", zap.Error(err))
			return false, v1.NewUnknownError(err.Error())
		}
	}
	if len(deletions) > 0 {
		err = s.jimm.PermissionManager().RemoveRelation(ctx, user, deletions)
		if err != nil {
			zapctx.Error(context.Background(), "cannot remove relations", zap.Error(err))
			return false, v1.NewUnknownError(err.Error())
		}
	}
	return true, nil
}

// // GetIdentityEntitlements returns a page of Entitlements for identity `identityId`.
func (s *identitiesService) GetIdentityEntitlements(ctx context.Context, identityId string, params *resources.GetIdentitiesItemEntitlementsParams) (*resources.PaginatedResponse[resources.EntityEntitlement], error) {
	user, err := utils.GetUserFromContext(ctx)
	if err != nil {
		return nil, err
	}
	objUser, err := s.jimm.IdentityManager().FetchIdentity(ctx, identityId)
	if err != nil {
		if errors.ErrorCode(err) == errors.CodeNotFound {
			return nil, v1.NewNotFoundError(fmt.Sprintf("User with id %s not found", identityId))
		}
		return nil, err
	}

	filter := utils.CreateTokenPaginationFilter(params.Size, params.NextToken, params.NextPageToken)
	entitlementToken := pagination.NewEntitlementToken(filter.Token())
	tuples, nextEntitlmentToken, err := s.jimm.PermissionManager().ListObjectRelations(ctx, user, objUser.Tag().String(), int32(filter.Limit()), entitlementToken) // #nosec G115 accept integer conversion
	if err != nil {
		return nil, err
	}
	originalToken := filter.Token()
	resp := resources.PaginatedResponse[resources.EntityEntitlement]{
		Meta: resources.ResponseMeta{
			Size:      len(tuples),
			PageToken: &originalToken,
		},
		Data: utils.ToEntityEntitlements(tuples),
	}
	if nextEntitlmentToken.String() != "" {
		nextToken := nextEntitlmentToken.String()
		resp.Next = resources.Next{
			PageToken: &nextToken,
		}
	}
	return &resp, nil
}

// PatchIdentityEntitlements performs addition or removal of an Entitlement to/from an Identity.
func (s *identitiesService) PatchIdentityEntitlements(ctx context.Context, identityId string, entitlementPatches []resources.IdentityEntitlementsPatchItem) (bool, error) {
	user, err := utils.GetUserFromContext(ctx)
	if err != nil {
		return false, err
	}
	objUser, err := s.jimm.IdentityManager().FetchIdentity(ctx, identityId)
	if err != nil {
		return false, v1.NewNotFoundError(fmt.Sprintf("User with id %s not found", identityId))
	}
	var toAdd []apiparams.RelationshipTuple
	var toRemove []apiparams.RelationshipTuple
	var errList utils.MultiErr
	toTargetTag := func(entitlementPatch resources.IdentityEntitlementsPatchItem) (names.Tag, error) {
		return utils.ValidateDecomposedTag(
			entitlementPatch.Entitlement.EntityType,
			entitlementPatch.Entitlement.EntityId,
		)
	}
	for _, entitlementPatch := range entitlementPatches {
		targetTag, err := toTargetTag(entitlementPatch)
		if err != nil {
			errList.AppendError(err)
			continue
		}
		t := apiparams.RelationshipTuple{
			Object:       objUser.Tag().String(),
			Relation:     entitlementPatch.Entitlement.Entitlement,
			TargetObject: targetTag.String(),
		}
		if entitlementPatch.Op == resources.IdentityEntitlementsPatchItemOpAdd {
			toAdd = append(toAdd, t)
		} else {
			toRemove = append(toRemove, t)
		}
	}
	if err := errList.Error(); err != nil {
		return false, err
	}
	if toAdd != nil {
		err := s.jimm.PermissionManager().AddRelation(ctx, user, toAdd)
		if err != nil {
			return false, err
		}
	}
	if toRemove != nil {
		err := s.jimm.PermissionManager().RemoveRelation(ctx, user, toRemove)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}
