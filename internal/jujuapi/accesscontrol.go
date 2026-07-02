// Copyright 2025 Canonical.

package jujuapi

import (
	"context"
	"fmt"
	"strconv"

	"github.com/juju/zaputil/zapctx"
	"go.uber.org/zap"

	apiparams "github.com/canonical/jimm/v3/pkg/api/params"
)

// access_control contains the primary RPC commands for handling ReBAC within JIMM via the JIMM facade itself.

const (
	jimmControllerName = "jimm"
)

// AddRelation creates a tuple between two objects [if applicable]
// within OpenFGA.
func (r *controllerRoot) AddRelation(ctx context.Context, req apiparams.AddRelationRequest) error {

	if err := r.jimm.PermissionManager().AddRelation(ctx, r.user, req.Tuples); err != nil {
		return fmt.Errorf("failed to add relation: %w", err)
	}
	return nil
}

// RemoveRelation removes a tuple between two objects [if applicable]
// within OpenFGA.
func (r *controllerRoot) RemoveRelation(ctx context.Context, req apiparams.RemoveRelationRequest) error {

	err := r.jimm.PermissionManager().RemoveRelation(ctx, r.user, req.Tuples)
	if err != nil {
		return fmt.Errorf("failed to remove relation: %w", err)
	}
	return nil
}

// CheckRelation performs an authorisation check for a particular group/user tuple
// against another tuple within OpenFGA.
// This corresponds directly to /stores/{store_id}/check.
func (r *controllerRoot) CheckRelation(ctx context.Context, req apiparams.CheckRelationRequest) (apiparams.CheckRelationResponse, error) {

	checkResp := apiparams.CheckRelationResponse{Allowed: false}

	allowed, err := r.jimm.PermissionManager().CheckRelation(ctx, r.user, req.Tuple, false)
	if err != nil {
		checkResp.Error = err.Error()
		return checkResp, fmt.Errorf("failed to check relation: %w", err)
	}
	checkResp.Allowed = allowed
	zapctx.Debug(ctx, "check request", zap.String("allowed", strconv.FormatBool(allowed)))
	return checkResp, nil
}

// CheckRelations performs an authorisation check for a list of tuples.
// It returns a list of results, each with an Allowed boolean and an optional error message.
func (r *controllerRoot) CheckRelations(ctx context.Context, req apiparams.CheckRelationsRequest) (apiparams.CheckRelationsResponse, error) {

	checksResp := apiparams.CheckRelationsResponse{}

	results, err := r.jimm.PermissionManager().CheckRelations(ctx, r.user, req.Tuples)
	if err != nil {
		return checksResp, fmt.Errorf("failed to check relations: %w", err)
	}
	for _, result := range results {
		resp := apiparams.CheckRelationResponse{
			Allowed: result.Allowed,
		}
		if result.Error != nil {
			resp.Error = result.Error.Error()
		}
		checksResp.Results = append(checksResp.Results, resp)
	}

	return checksResp, nil
}

// ListRelationshipTuples returns a list of tuples matching the specified filter.
func (r *controllerRoot) ListRelationshipTuples(ctx context.Context, req apiparams.ListRelationshipTuplesRequest) (apiparams.ListRelationshipTuplesResponse, error) {

	responseTuples, ct, err := r.jimm.PermissionManager().ListRelationshipTuples(ctx, r.user, req.Tuple, req.PageSize, req.ContinuationToken)
	if err != nil {
		return apiparams.ListRelationshipTuplesResponse{}, fmt.Errorf("failed to list relations: %w", err)
	}
	errors := []string{}
	tuples := make([]apiparams.RelationshipTuple, len(responseTuples))
	for i, t := range responseTuples {
		object, err := r.jimm.PermissionManager().ToJAASTag(ctx, t.Object, req.ResolveUUIDs)
		if err != nil {
			object = t.Object.String()
			errors = append(errors, "failed to parse object: "+err.Error())
		}
		target, err := r.jimm.PermissionManager().ToJAASTag(ctx, t.Target, req.ResolveUUIDs)
		if err != nil {
			target = t.Target.String()
			errors = append(errors, "failed to parse target: "+err.Error())
		}
		tuples[i] = apiparams.RelationshipTuple{
			Object:       object,
			Relation:     string(t.Relation),
			TargetObject: target,
		}
	}
	return apiparams.ListRelationshipTuplesResponse{
		Tuples:            tuples,
		ContinuationToken: ct,
		Errors:            errors,
	}, nil
}
