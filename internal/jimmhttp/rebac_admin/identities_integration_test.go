// Copyright 2025 Canonical.
package rebac_admin_test

import (
	"context"
	"fmt"

	rebac_handlers "github.com/canonical/rebac-admin-ui-handlers/v1"
	"github.com/canonical/rebac-admin-ui-handlers/v1/resources"
	"github.com/juju/names/v5"
	gc "gopkg.in/check.v1"

	"github.com/canonical/jimm/v3/internal/dbmodel"
	"github.com/canonical/jimm/v3/internal/jimmhttp/rebac_admin"
	"github.com/canonical/jimm/v3/internal/openfga"
	ofganames "github.com/canonical/jimm/v3/internal/openfga/names"
	"github.com/canonical/jimm/v3/internal/testutils/jimmtest"
	"github.com/canonical/jimm/v3/pkg/api/params"
	jimmnames "github.com/canonical/jimm/v3/pkg/names"
)

type identitiesSuite struct {
	jimmtest.JIMMSuite
}

var _ = gc.Suite(&identitiesSuite{})

func (s *identitiesSuite) TestIdentitiesList(c *gc.C) {
	ctx := context.Background()
	ctx = rebac_handlers.ContextWithIdentity(ctx, s.AdminUser)
	identitySvc := rebac_admin.NewidentitiesService(s.JIMM)
	for i := range 5 {
		user := names.NewUserTag(fmt.Sprintf("test-user-match-%d@canonical.com", i))
		s.AddUser(c, user.Id())
	}
	pageSize := 5
	page := 0
	params := &resources.GetIdentitiesParams{Size: &pageSize, Page: &page}
	res, err := identitySvc.ListIdentities(ctx, params)
	c.Assert(err, gc.IsNil)
	c.Assert(res, gc.Not(gc.IsNil))
	c.Assert(res.Meta.Size, gc.Equals, 5)

	match := "test-user-match-1"
	params.Filter = &match
	res, err = identitySvc.ListIdentities(ctx, params)
	c.Assert(err, gc.IsNil)
	c.Assert(res, gc.Not(gc.IsNil))
	c.Assert(len(res.Data), gc.Equals, 1)

	match = "test-user"
	params.Filter = &match
	res, err = identitySvc.ListIdentities(ctx, params)
	c.Assert(err, gc.IsNil)
	c.Assert(res, gc.Not(gc.IsNil))
	c.Assert(len(res.Data), gc.Equals, pageSize)
}

func (s *identitiesSuite) TestIdentityPatchGroups(c *gc.C) {
	// initialization
	ctx := context.Background()
	ctx = rebac_handlers.ContextWithIdentity(ctx, s.AdminUser)
	identitySvc := rebac_admin.NewidentitiesService(s.JIMM)
	groupName := "group-test1"
	username := s.AdminUser.Name
	group := s.AddGroup(c, groupName)

	// test add identity group
	changed, err := identitySvc.PatchIdentityGroups(ctx, username, []resources.IdentityGroupsPatchItem{{
		Group: group.UUID,
		Op:    resources.IdentityGroupsPatchItemOpAdd,
	}})
	c.Assert(err, gc.IsNil)
	c.Assert(changed, gc.Equals, true)

	// test user added to groups
	objUser, err := s.JIMM.IdentityManager().FetchIdentity(ctx, username)
	c.Assert(err, gc.IsNil)
	tuples, _, err := s.JIMM.PermissionManager().ListRelationshipTuples(ctx, s.AdminUser, params.RelationshipTuple{
		Object:       objUser.ResourceTag().String(),
		Relation:     ofganames.MemberRelation.String(),
		TargetObject: group.ResourceTag().String(),
	}, 10, "")
	c.Assert(err, gc.IsNil)
	c.Assert(len(tuples), gc.Equals, 1)
	c.Assert(group.UUID, gc.Equals, tuples[0].Target.ID)

	// test user remove from group
	changed, err = identitySvc.PatchIdentityGroups(ctx, username, []resources.IdentityGroupsPatchItem{{
		Group: group.UUID,
		Op:    resources.IdentityGroupsPatchItemOpRemove,
	}})
	c.Assert(err, gc.IsNil)
	c.Assert(changed, gc.Equals, true)
	tuples, _, err = s.JIMM.PermissionManager().ListRelationshipTuples(ctx, s.AdminUser, params.RelationshipTuple{
		Object:       objUser.ResourceTag().String(),
		Relation:     ofganames.MemberRelation.String(),
		TargetObject: group.ResourceTag().String(),
	}, 10, "")
	c.Assert(err, gc.IsNil)
	c.Assert(len(tuples), gc.Equals, 0)
}

func (s *identitiesSuite) TestIdentityGetGroups(c *gc.C) {
	// initialization
	ctx := context.Background()
	ctx = rebac_handlers.ContextWithIdentity(ctx, s.AdminUser)
	identitySvc := rebac_admin.NewidentitiesService(s.JIMM)
	username := s.AdminUser.Name
	groupsSize := 10
	groupsToAdd := make([]resources.IdentityGroupsPatchItem, groupsSize)
	groupTags := make([]jimmnames.GroupTag, groupsSize)
	for i := range groupsSize {
		groupName := fmt.Sprintf("group-test%d", i)
		group := s.AddGroup(c, groupName)
		groupTags[i] = group.ResourceTag()
		groupsToAdd[i] = resources.IdentityGroupsPatchItem{
			Group: group.UUID,
			Op:    resources.IdentityGroupsPatchItemOpAdd,
		}

	}
	changed, err := identitySvc.PatchIdentityGroups(ctx, username, groupsToAdd)
	c.Assert(err, gc.IsNil)
	c.Assert(changed, gc.Equals, true)

	// test list identity's groups with token pagination
	size := 3
	token := ""
	totalGroups := 0
	for i := 0; ; i += size {
		groups, err := identitySvc.GetIdentityGroups(ctx, username, &resources.GetIdentitiesItemGroupsParams{
			Size:      &size,
			NextToken: &token,
		})
		c.Assert(err, gc.IsNil)
		for j := 0; j < len(groups.Data); j++ {
			totalGroups++
			c.Assert(groups.Data[j].Name, gc.Matches, `group-test\d+`)
			c.Assert(groupTags[j].Id(), gc.Matches, `\w*-\w*-\w*-\w*-\w*`)
		}
		if groups.Next.PageToken == nil || *groups.Next.PageToken == "" {
			break
		}
		token = *groups.Next.PageToken
	}
	c.Assert(totalGroups, gc.Equals, groupsSize)
}

// TestGetIdentityGroupsWithDeletedDbGroup tests the behaviour
// of GetIdentityGroups when a tuple lingers in OpenFGA but the group
// has been removed from the database.
func (s *identitiesSuite) TestGetIdentityGroupsWithDeletedDbGroup(c *gc.C) {
	ctx := context.Background()
	ctx = rebac_handlers.ContextWithIdentity(ctx, s.AdminUser)
	identitySvc := rebac_admin.NewidentitiesService(s.JIMM)
	username := s.AdminUser.Name

	group1 := s.AddGroup(c, "group1")
	group2 := s.AddGroup(c, "group2")

	baseTuple := openfga.Tuple{
		Object:   ofganames.ConvertTag(s.AdminUser.ResourceTag()),
		Relation: ofganames.MemberRelation,
	}
	group1Access := baseTuple
	group1Access.Target = ofganames.ConvertTag(group1.ResourceTag())
	group2Access := baseTuple
	group2Access.Target = ofganames.ConvertTag(group2.ResourceTag())

	err := s.JIMM.OpenFGAClient.AddRelation(ctx, group1Access, group2Access)
	c.Assert(err, gc.IsNil)

	groups, err := identitySvc.GetIdentityGroups(ctx, username, &resources.GetIdentitiesItemGroupsParams{})
	c.Assert(err, gc.IsNil)
	c.Assert(groups.Data, gc.HasLen, 2)

	groupToDelete := dbmodel.GroupEntry{Name: "group2"}
	err = s.JIMM.Database.GetGroup(ctx, &groupToDelete)
	c.Assert(err, gc.IsNil)
	err = s.JIMM.Database.RemoveGroup(ctx, &groupToDelete)
	c.Assert(err, gc.IsNil)

	groups, err = identitySvc.GetIdentityGroups(ctx, username, &resources.GetIdentitiesItemGroupsParams{})
	c.Assert(err, gc.IsNil)
	c.Assert(groups.Data, gc.HasLen, 1)
}

func (s *identitiesSuite) TestIdentityPatchRoles(c *gc.C) {
	// initialization
	ctx := context.Background()
	ctx = rebac_handlers.ContextWithIdentity(ctx, s.AdminUser)
	identitySvc := rebac_admin.NewidentitiesService(s.JIMM)
	roleName := "role-test1"
	username := s.AdminUser.Name
	role := s.AddRole(c, roleName)

	// test add identity role
	changed, err := identitySvc.PatchIdentityRoles(ctx, username, []resources.IdentityRolesPatchItem{{
		Role: role.UUID,
		Op:   resources.IdentityRolesPatchItemOpAdd,
	}})
	c.Assert(err, gc.IsNil)
	c.Assert(changed, gc.Equals, true)

	// test user added to roles
	objUser, err := s.JIMM.IdentityManager().FetchIdentity(ctx, username)
	c.Assert(err, gc.IsNil)
	tuples, _, err := s.JIMM.PermissionManager().ListRelationshipTuples(ctx, s.AdminUser, params.RelationshipTuple{
		Object:       objUser.ResourceTag().String(),
		Relation:     ofganames.AssigneeRelation.String(),
		TargetObject: role.ResourceTag().String(),
	}, 10, "")
	c.Assert(err, gc.IsNil)
	c.Assert(len(tuples), gc.Equals, 1)
	c.Assert(role.UUID, gc.Equals, tuples[0].Target.ID)

	// test user remove from role
	changed, err = identitySvc.PatchIdentityRoles(ctx, username, []resources.IdentityRolesPatchItem{{
		Role: role.UUID,
		Op:   resources.IdentityRolesPatchItemOpRemove,
	}})
	c.Assert(err, gc.IsNil)
	c.Assert(changed, gc.Equals, true)
	tuples, _, err = s.JIMM.PermissionManager().ListRelationshipTuples(ctx, s.AdminUser, params.RelationshipTuple{
		Object:       objUser.ResourceTag().String(),
		Relation:     ofganames.AssigneeRelation.String(),
		TargetObject: role.ResourceTag().String(),
	}, 10, "")
	c.Assert(err, gc.IsNil)
	c.Assert(len(tuples), gc.Equals, 0)
}

func (s *identitiesSuite) TestIdentityGetRoles(c *gc.C) {
	// initialization
	ctx := context.Background()
	ctx = rebac_handlers.ContextWithIdentity(ctx, s.AdminUser)
	identitySvc := rebac_admin.NewidentitiesService(s.JIMM)
	username := s.AdminUser.Name
	rolesSize := 10
	rolesToAdd := make([]resources.IdentityRolesPatchItem, rolesSize)
	roleTags := make([]jimmnames.RoleTag, rolesSize)
	for i := range rolesSize {
		roleName := fmt.Sprintf("role-test%d", i)
		role := s.AddRole(c, roleName)
		roleTags[i] = role.ResourceTag()
		rolesToAdd[i] = resources.IdentityRolesPatchItem{
			Role: role.UUID,
			Op:   resources.IdentityRolesPatchItemOpAdd,
		}

	}
	changed, err := identitySvc.PatchIdentityRoles(ctx, username, rolesToAdd)
	c.Assert(err, gc.IsNil)
	c.Assert(changed, gc.Equals, true)

	// test list identity's roles with token pagination
	size := 3
	token := ""
	totalRoles := 0
	for i := 0; ; i += size {
		roles, err := identitySvc.GetIdentityRoles(ctx, username, &resources.GetIdentitiesItemRolesParams{
			Size:      &size,
			NextToken: &token,
		})
		c.Assert(err, gc.IsNil)
		for j := 0; j < len(roles.Data); j++ {
			totalRoles++
			c.Assert(roles.Data[j].Name, gc.Matches, `role-test\d+`)
			c.Assert(roleTags[j].Id(), gc.Matches, `\w*-\w*-\w*-\w*-\w*`)
		}
		if roles.Next.PageToken == nil || *roles.Next.PageToken == "" {
			break
		}
		token = *roles.Next.PageToken
	}
	c.Assert(totalRoles, gc.Equals, rolesSize)
}

// TestIdentityEntitlements tests the listing of entitlements for a specific identityId.
// Setup: add controllers, models to a user and add the user to a group.
func (s *identitiesSuite) TestIdentityEntitlements(c *gc.C) {
	// initialization
	ctx := context.Background()
	identitySvc := rebac_admin.NewidentitiesService(s.JIMM)
	group := s.AddGroup(c, "test-group")
	user := names.NewUserTag("test-user@canonical.com")
	s.AddUser(c, user.Id())
	err := s.JIMM.OpenFGAClient.AddRelation(ctx, openfga.Tuple{
		Object:   ofganames.ConvertTag(user),
		Relation: ofganames.MemberRelation,
		Target:   ofganames.ConvertTag(group.ResourceTag()),
	})
	c.Assert(err, gc.IsNil)
	tuple := openfga.Tuple{
		Object:   ofganames.ConvertTag(user),
		Relation: ofganames.AdministratorRelation,
	}
	var tuples []openfga.Tuple
	for i := range 3 {
		t := tuple
		t.Target = ofganames.ConvertTag(names.NewModelTag(fmt.Sprintf("test-model-%d", i)))
		tuples = append(tuples, t)
	}
	for i := range 3 {
		t := tuple
		t.Target = ofganames.ConvertTag(names.NewControllerTag(fmt.Sprintf("test-controller-%d", i)))
		tuples = append(tuples, t)
	}
	err = s.JIMM.OpenFGAClient.AddRelation(ctx, tuples...)
	c.Assert(err, gc.IsNil)

	// test
	ctx = rebac_handlers.ContextWithIdentity(ctx, s.AdminUser)
	emptyPageToken := ""
	req := resources.GetIdentitiesItemEntitlementsParams{NextPageToken: &emptyPageToken}
	var entitlements []resources.EntityEntitlement
	res, err := identitySvc.GetIdentityEntitlements(ctx, user.Id(), &req)
	c.Assert(err, gc.IsNil)
	c.Assert(res, gc.Not(gc.IsNil))
	entitlements = append(entitlements, res.Data...)
	c.Assert(entitlements, gc.HasLen, 7)
	modelEntitlementCount := 0
	controllerEntitlementCount := 0
	groupEntitlementCount := 0
	for _, entitlement := range entitlements {
		switch entitlement.EntityType {
		case openfga.ModelType.String():
			c.Assert(entitlement.EntityId, gc.Matches, `test-model-\d`)
			c.Assert(entitlement.Entitlement, gc.Equals, ofganames.AdministratorRelation.String())
			modelEntitlementCount++
		case openfga.ControllerType.String():
			c.Assert(entitlement.EntityId, gc.Matches, `test-controller-\d`)
			c.Assert(entitlement.Entitlement, gc.Equals, ofganames.AdministratorRelation.String())
			controllerEntitlementCount++
		case openfga.GroupType.String():
			c.Assert(entitlement.Entitlement, gc.Equals, ofganames.MemberRelation.String())
			groupEntitlementCount++
		default:
			c.Logf("Unexpected entitlement found of type %s", entitlement.EntityType)
			c.FailNow()
		}
	}
	c.Assert(modelEntitlementCount, gc.Equals, 3)
	c.Assert(controllerEntitlementCount, gc.Equals, 3)
	c.Assert(groupEntitlementCount, gc.Equals, 1)
}

// patchIdentitiesEntitlementTestEnv is used to create entries in JIMM's database.
// The rebacAdminSuite does not spin up a Juju controller so we cannot use
// regular JIMM methods to create resources. It is also necessary to have resources
// present in the database in order for ListRelationshipTuples to work correctly.
const patchIdentitiesEntitlementTestEnv = `clouds:
- name: test-cloud
  type: test-provider
  regions:
  - name: test-cloud-region
cloud-credentials:
- owner: alice@canonical.com
  name: cred-1
  cloud: test-cloud
controllers:
- name: controller-1
  uuid: 00000001-0000-0000-0000-000000000001
  cloud: test-cloud
  region: test-cloud-region
models:
- name: model-1
  uuid: 00000002-0000-0000-0000-000000000001
  controller: controller-1
  cloud: test-cloud
  region: test-cloud-region
  cloud-credential: cred-1
  owner: alice@canonical.com
- name: model-2
  uuid: 00000002-0000-0000-0000-000000000002
  controller: controller-1
  cloud: test-cloud
  region: test-cloud-region
  cloud-credential: cred-1
  owner: alice@canonical.com
- name: model-3
  uuid: 00000003-0000-0000-0000-000000000003
  controller: controller-1
  cloud: test-cloud
  region: test-cloud-region
  cloud-credential: cred-1
  owner: alice@canonical.com
- name: model-4
  uuid: 00000004-0000-0000-0000-000000000004
  controller: controller-1
  cloud: test-cloud
  region: test-cloud-region
  cloud-credential: cred-1
  owner: alice@canonical.com
`

// TestPatchIdentityEntitlements tests the patching of entitlements for a specific identityId,
// adding and removing relations after the setup.
// Setup: add user to a group, and add models to the user.
func (s *identitiesSuite) TestPatchIdentityEntitlements(c *gc.C) {
	// initialization
	ctx := context.Background()
	identitySvc := rebac_admin.NewidentitiesService(s.JIMM)
	tester := jimmtest.GocheckTester{C: c}
	env := jimmtest.ParseEnvironment(tester, patchIdentitiesEntitlementTestEnv)
	env.PopulateDB(tester, s.JIMM.Database)
	oldModels := []string{env.Models[0].UUID, env.Models[1].UUID}
	newModels := []string{env.Models[2].UUID, env.Models[3].UUID}
	user := names.NewUserTag("test-user@canonical.com")
	s.AddUser(c, user.Id())
	tuple := openfga.Tuple{
		Object:   ofganames.ConvertTag(user),
		Relation: ofganames.AdministratorRelation,
	}

	var tuples []openfga.Tuple
	for i := range 2 {
		t := tuple
		t.Target = ofganames.ConvertTag(names.NewModelTag(oldModels[i]))
		tuples = append(tuples, t)
	}
	err := s.JIMM.OpenFGAClient.AddRelation(ctx, tuples...)
	c.Assert(err, gc.IsNil)
	allowed, err := s.JIMM.OpenFGAClient.CheckRelation(ctx, tuples[0], false)
	c.Assert(err, gc.IsNil)
	c.Assert(allowed, gc.Equals, true)
	// Above we have added granted the user with administrator permission to 2 models.
	// Below, we will request those 2 relations to be removed and add 2 different relations.

	entitlementPatches := []resources.IdentityEntitlementsPatchItem{
		{Entitlement: resources.EntityEntitlement{
			Entitlement: ofganames.AdministratorRelation.String(),
			EntityId:    newModels[0],
			EntityType:  openfga.ModelType.String(),
		}, Op: resources.IdentityEntitlementsPatchItemOpAdd},
		{Entitlement: resources.EntityEntitlement{
			Entitlement: ofganames.AdministratorRelation.String(),
			EntityId:    newModels[1],
			EntityType:  openfga.ModelType.String(),
		}, Op: resources.IdentityEntitlementsPatchItemOpAdd},
		{Entitlement: resources.EntityEntitlement{
			Entitlement: ofganames.AdministratorRelation.String(),
			EntityId:    oldModels[0],
			EntityType:  openfga.ModelType.String(),
		}, Op: resources.IdentityEntitlementsPatchItemOpRemove},
		{Entitlement: resources.EntityEntitlement{
			Entitlement: ofganames.AdministratorRelation.String(),
			EntityId:    oldModels[1],
			EntityType:  openfga.ModelType.String(),
		}, Op: resources.IdentityEntitlementsPatchItemOpRemove},
	}
	ctx = rebac_handlers.ContextWithIdentity(ctx, s.AdminUser)
	res, err := identitySvc.PatchIdentityEntitlements(ctx, user.Id(), entitlementPatches)
	c.Assert(err, gc.IsNil)
	c.Assert(res, gc.Equals, true)

	for i := range 2 {
		exists, err := s.JIMM.OpenFGAClient.CheckRelation(ctx, tuples[i], false)
		c.Assert(err, gc.IsNil)
		c.Assert(exists, gc.Equals, false)
	}
	for i := range 2 {
		newTuple := tuples[0]
		newTuple.Target = ofganames.ConvertTag(names.NewModelTag(newModels[i]))
		allowed, err = s.JIMM.OpenFGAClient.CheckRelation(ctx, newTuple, false)
		c.Assert(err, gc.IsNil)
		c.Assert(allowed, gc.Equals, true)
	}
}

// TestPatchIdentityEntitlementsForCloudAccess tests granting access to a cloud.
func (s *identitiesSuite) TestPatchIdentityEntitlementsForCloudAccess(c *gc.C) {
	// initialization
	ctx := context.Background()
	identitySvc := rebac_admin.NewidentitiesService(s.JIMM)
	tester := jimmtest.GocheckTester{C: c}
	env := jimmtest.ParseEnvironment(tester, patchIdentitiesEntitlementTestEnv)
	env.PopulateDB(tester, s.JIMM.Database)
	user := names.NewUserTag("test-user@canonical.com")
	s.AddUser(c, user.Id())

	cloudEntitlement := []resources.IdentityEntitlementsPatchItem{
		{Entitlement: resources.EntityEntitlement{
			Entitlement: ofganames.AdministratorRelation.String(),
			EntityId:    "test-cloud",
			EntityType:  openfga.CloudType.String(),
		}, Op: resources.IdentityEntitlementsPatchItemOpAdd},
	}
	ctx = rebac_handlers.ContextWithIdentity(ctx, s.AdminUser)
	res, err := identitySvc.PatchIdentityEntitlements(ctx, user.Id(), cloudEntitlement)
	c.Assert(err, gc.IsNil)
	c.Assert(res, gc.Equals, true)

	tuple := openfga.Tuple{
		Object:   ofganames.ConvertTag(user),
		Relation: ofganames.AdministratorRelation,
		Target:   ofganames.ConvertTag(names.NewCloudTag("test-cloud")),
	}
	exists, err := s.JIMM.OpenFGAClient.CheckRelation(ctx, tuple, false)
	c.Assert(err, gc.IsNil)
	c.Assert(exists, gc.Equals, true)
}
