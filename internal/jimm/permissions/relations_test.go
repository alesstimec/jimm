// Copyright 2025 Canonical.

package permissions_test

import (
	"context"

	qt "github.com/frankban/quicktest"

	"github.com/canonical/jimm/v3/internal/common/pagination"
	"github.com/canonical/jimm/v3/internal/dbmodel"
	"github.com/canonical/jimm/v3/internal/openfga"
	"github.com/canonical/jimm/v3/internal/openfga/names"
	"github.com/canonical/jimm/v3/internal/testutils/jimmtest"
	apiparams "github.com/canonical/jimm/v3/pkg/api/params"
)

func (s *permissionManagerSuite) TestListRelationshipTuples(c *qt.C) {
	c.Parallel()
	ctx := context.Background()

	u := openfga.NewUser(&dbmodel.Identity{Name: "admin@canonical.com"}, s.ofgaClient)
	u.JimmAdmin = true

	user, _, controller, model, _, _, _, _ := jimmtest.CreateTestControllerEnvironment(ctx, c, s.db)

	err := s.manager.AddRelation(ctx, u, []apiparams.RelationshipTuple{
		{
			Object:       user.Tag().String(),
			Relation:     names.ReaderRelation.String(),
			TargetObject: model.ResourceTag().String(),
		},
		{
			Object:       user.Tag().String(),
			Relation:     names.WriterRelation.String(),
			TargetObject: model.ResourceTag().String(),
		},
		{
			Object:       user.Tag().String(),
			Relation:     names.AuditLogViewerRelation.String(),
			TargetObject: controller.ResourceTag().String(),
		},
	})
	c.Assert(err, qt.IsNil)

	type ExpectedTuple struct {
		expectedRelation string
		expectedTargetId string
	}
	// test
	testCases := []struct {
		description    string
		object         string
		relation       string
		targetObject   string
		expectedError  error
		expectedLength int
		expectedTuples []ExpectedTuple
	}{
		{
			description:    "test listing all relations of all entities",
			object:         "",
			relation:       "",
			targetObject:   "",
			expectedError:  nil,
			expectedLength: 4,
		},
		{
			description:    "test listing a specific relation",
			object:         user.Tag().String(),
			relation:       names.ReaderRelation.String(),
			targetObject:   model.ResourceTag().String(),
			expectedError:  nil,
			expectedLength: 1,
			expectedTuples: []ExpectedTuple{
				{

					expectedRelation: names.ReaderRelation.String(),
					expectedTargetId: model.Tag().Id(),
				},
			},
		},
		{
			description:    "test listing all relations between two entities leaving relation empty",
			object:         user.Tag().String(),
			relation:       "",
			targetObject:   model.ResourceTag().String(),
			expectedError:  nil,
			expectedLength: 2,
			expectedTuples: []ExpectedTuple{
				{
					expectedRelation: names.ReaderRelation.String(),
					expectedTargetId: model.Tag().Id(),
				},
				{
					expectedRelation: names.WriterRelation.String(),
					expectedTargetId: model.Tag().Id(),
				},
			},
		},
		{
			description:    "test listing all relations of a specific target entity",
			object:         "",
			relation:       "",
			targetObject:   model.ResourceTag().String(),
			expectedError:  nil,
			expectedLength: 2,
			expectedTuples: []ExpectedTuple{
				{
					expectedRelation: names.ReaderRelation.String(),
					expectedTargetId: model.Tag().Id(),
				},
				{
					expectedRelation: names.WriterRelation.String(),
					expectedTargetId: model.Tag().Id(),
				},
			},
		},
		{
			description:    "test listing all relations of specific object entity",
			object:         user.ResourceTag().String(),
			relation:       names.ReaderRelation.String(),
			targetObject:   "model",
			expectedError:  nil,
			expectedLength: 1,
			expectedTuples: []ExpectedTuple{
				{
					expectedRelation: names.ReaderRelation.String(),
					expectedTargetId: model.Tag().Id(),
				},
			},
		},
	}

	for _, t := range testCases {
		c.Run(t.description, func(c *qt.C) {
			tuples, _, err := s.manager.ListRelationshipTuples(ctx, s.adminUser, apiparams.RelationshipTuple{
				Object:       t.object,
				Relation:     t.relation,
				TargetObject: t.targetObject,
			}, 10, "")
			c.Assert(err, qt.Equals, t.expectedError)
			c.Assert(tuples, qt.HasLen, t.expectedLength)
			for i, expectedTuple := range t.expectedTuples {
				c.Assert(tuples[i].Relation.String(), qt.Equals, expectedTuple.expectedRelation)
				c.Assert(tuples[i].Target.ID, qt.Equals, expectedTuple.expectedTargetId)
			}
		})
	}
}

func (s *permissionManagerSuite) TestListObjectRelations(c *qt.C) {
	c.Parallel()
	ctx := context.Background()

	u := openfga.NewUser(&dbmodel.Identity{Name: "admin@canonical.com"}, s.ofgaClient)
	u.JimmAdmin = true

	user, group, controller, model, _, cloud, _, _ := jimmtest.CreateTestControllerEnvironment(ctx, c, s.db)

	err := s.manager.AddRelation(ctx, u, []apiparams.RelationshipTuple{
		{
			Object:       user.Tag().String(),
			Relation:     names.ReaderRelation.String(),
			TargetObject: model.ResourceTag().String(),
		},
		{
			Object:       user.Tag().String(),
			Relation:     names.WriterRelation.String(),
			TargetObject: model.ResourceTag().String(),
		},
		{
			Object:       user.Tag().String(),
			Relation:     names.AuditLogViewerRelation.String(),
			TargetObject: controller.ResourceTag().String(),
		},
		{
			Object:       user.Tag().String(),
			Relation:     names.AdministratorRelation.String(),
			TargetObject: controller.ResourceTag().String(),
		},
		{
			Object:       user.Tag().String(),
			Relation:     names.AdministratorRelation.String(),
			TargetObject: cloud.ResourceTag().String(),
		},
		{
			Object:       user.Tag().String(),
			Relation:     names.CanAddModelRelation.String(),
			TargetObject: cloud.ResourceTag().String(),
		},
		{
			Object:       user.Tag().String(),
			Relation:     names.MemberRelation.String(),
			TargetObject: group.ResourceTag().String(),
		},
	})

	c.Assert(err, qt.IsNil)
	type ExpectedTuple struct {
		expectedRelation string
		expectedTargetId string
	}

	testCases := []struct {
		description          string
		object               string
		initialToken         pagination.EntitlementToken
		pageSize             int32
		expectNumPages       int
		expectedError        string
		expectedTuplesLength int
		expectedTuples       []ExpectedTuple
	}{
		{
			description:          "test listing all relations in single page",
			object:               user.Tag().String(),
			pageSize:             10,
			expectNumPages:       1,
			expectedTuplesLength: 7,
		},
		{
			description:          "test listing all relations in multiple pages",
			object:               user.Tag().String(),
			pageSize:             2,
			expectNumPages:       4,
			expectedTuplesLength: 7,
		},
		{
			description:   "invalid initial token",
			object:        user.Tag().String(),
			initialToken:  pagination.NewEntitlementToken("bar"),
			expectedError: "failed to decode pagination token.*",
		},
		{
			description:   "invalid user tag token",
			object:        "foo" + user.Tag().String(),
			expectedError: "failed to map tag, unknown kind: foouser",
		},
	}

	for _, t := range testCases {
		c.Run(t.description, func(c *qt.C) {
			token := t.initialToken
			tuples := []openfga.Tuple{}
			numPages := 0
			for {
				res, nextToken, err := s.manager.ListObjectRelations(ctx, s.adminUser, t.object, t.pageSize, token)
				if t.expectedError != "" {
					c.Assert(err, qt.ErrorMatches, t.expectedError)
					break
				}
				tuples = append(tuples, res...)
				numPages += 1
				if nextToken.String() == "" {
					break
				}
				token = nextToken
			}
			c.Assert(numPages, qt.Equals, t.expectNumPages)
			c.Assert(tuples, qt.HasLen, t.expectedTuplesLength)
			for i, expectedTuple := range t.expectedTuples {
				c.Assert(tuples[i].Relation.String(), qt.Equals, expectedTuple.expectedRelation)
				c.Assert(tuples[i].Target.ID, qt.Equals, expectedTuple.expectedTargetId)
			}
		})
	}
}
