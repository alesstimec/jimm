// Copyright 2025 Canonical.

package testing

import (
	"database/sql"
	"testing"

	petname "github.com/dustinkirkland/golang-petname"
	qt "github.com/frankban/quicktest"
	"github.com/google/uuid"
	"github.com/juju/juju/api/client/modelmanager"
	"github.com/juju/juju/core/crossmodel"
	"github.com/juju/juju/core/life"
	jujuparams "github.com/juju/juju/rpc/params"
	"github.com/juju/names/v6"

	"github.com/canonical/jimm/v3/internal/dbmodel"
	"github.com/canonical/jimm/v3/internal/openfga"
	ofganames "github.com/canonical/jimm/v3/internal/openfga/names"
	"github.com/canonical/jimm/v3/internal/testutils/jimmtest"
	"github.com/canonical/jimm/v3/pkg/api"
	apiparams "github.com/canonical/jimm/v3/pkg/api/params"
	jimmnames "github.com/canonical/jimm/v3/pkg/names"
)

/*
 Relation facade related tests
*/

// createTuple wraps the underlying ofga tuple into a convenient ease-of-use method
func createTuple(object, relation, target string) openfga.Tuple {
	objectEntity, _ := openfga.ParseTag(object)
	targetEntity, _ := openfga.ParseTag(target)
	return openfga.Tuple{
		Object:   &objectEntity,
		Relation: openfga.Relation(relation),
		Target:   &targetEntity,
	}
}

// TestAddRelation currently verifies the following test cases,
// when new relation control is to be added, please update this comment:
// user -> controller (name)
// user -> controller (uuid)
// user -> model (name)
// user -> model (uuid)
// user -> applicationoffer (name)
// user -> applicationoffer (uuid)
// user -> idpgroup
// idpgroup#member -> controller (name)
// idpgroup#member -> controller (uuid)
// idpgroup#member -> model (name)
// idpgroup#member -> model (uuid)
// idpgroup#member -> applicationoffer (name)
// idpgroup#member -> applicationoffer (uuid)
func TestAddRelation(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	ctx := t.Context()

	user, controller, model, offer, _, _, client, closeClient := createTestControllerEnvironment(c, s)
	defer closeClient()

	type tuple struct {
		object   string
		relation string
		target   string
	}
	type tagTest struct {
		input       tuple
		want        openfga.Tuple
		err         bool
		changesType string
	}

	tagTests := []tagTest{
		// Test user -> controller by name
		{
			input: tuple{"user-" + user.Name, "administrator", "controller-" + controller.Name},
			want: createTuple(
				"user:"+user.Name,
				"administrator",
				"controller:"+controller.UUID,
			),
			err:         false,
			changesType: "controller",
		},
		// Test user -> controller jimm
		{
			input: tuple{"user-" + user.Name, "administrator", "controller-jimm"},
			want: createTuple(
				"user:"+user.Name,
				"administrator",
				"controller:"+s.JIMM.UUID,
			),
			err:         false,
			changesType: "controller",
		},
		// Test user -> controller by UUID
		{
			input: tuple{"user-" + user.Name, "administrator", "controller-" + controller.UUID},
			want: createTuple(
				"user:"+user.Name,
				"administrator",
				"controller:"+controller.UUID,
			),
			err:         false,
			changesType: "controller",
		},
		// Test user -> model by name
		{
			input: tuple{"user-" + user.Name, "writer", "model-" + user.Name + "/" + model.Name},
			want: createTuple(
				"user:"+user.Name,
				"writer",
				"model:"+model.UUID.String,
			),
			err:         false,
			changesType: "model",
		},
		// Test user -> model by UUID
		{
			input: tuple{"user-" + user.Name, "writer", "model-" + model.UUID.String},
			want: createTuple(
				"user:"+user.Name,
				"writer",
				"model:"+model.UUID.String,
			),
			err:         false,
			changesType: "model",
		},
		// Test user -> applicationoffer by name
		{
			input: tuple{"user-" + user.Name, "consumer", "applicationoffer-" + offer.URL},
			want: createTuple(
				"user:"+user.Name,
				"consumer",
				"applicationoffer:"+offer.UUID,
			),
			err:         false,
			changesType: "applicationoffer",
		},
		// Test user -> applicationoffer by UUID
		{
			input: tuple{"user-" + user.Name, "consumer", "applicationoffer-" + offer.UUID},
			want: createTuple(
				"user:"+user.Name,
				"consumer",
				"applicationoffer:"+offer.UUID,
			),
			err:         false,
			changesType: "applicationoffer",
		},
		// Test IDP group -> model by UUID.
		{
			input: tuple{"idpgroup-test-idpgroup#member", "reader", "model-" + model.UUID.String},
			want: createTuple(
				"idpgroup:test-idpgroup#member",
				"reader",
				"model:"+model.UUID.String,
			),
			err:         false,
			changesType: "model",
		},
		// Test user -> idpgroup
		{
			input: tuple{"user-" + user.Name, "member", "idpgroup-test-idpgroup"},
			want: createTuple(
				"user:"+user.Name,
				"member",
				"idpgroup:test-idpgroup",
			),
			err:         false,
			changesType: "idpgroup",
		},
		// Test idpgroup#member -> controller by name
		{
			input: tuple{"idpgroup-test-idpgroup#member", "administrator", "controller-" + controller.Name},
			want: createTuple(
				"idpgroup:test-idpgroup#member",
				"administrator",
				"controller:"+controller.UUID,
			),
			err:         false,
			changesType: "controller",
		},
		// Test idpgroup#member -> controller by UUID
		{
			input: tuple{"idpgroup-test-idpgroup#member", "administrator", "controller-" + controller.UUID},
			want: createTuple(
				"idpgroup:test-idpgroup#member",
				"administrator",
				"controller:"+controller.UUID,
			),
			err:         false,
			changesType: "controller",
		},
		// Test idpgroup#member -> model by name
		{
			input: tuple{"idpgroup-test-idpgroup#member", "writer", "model-" + user.Name + "/" + model.Name},
			want: createTuple(
				"idpgroup:test-idpgroup#member",
				"writer",
				"model:"+model.UUID.String,
			),
			err:         false,
			changesType: "model",
		},
		// Test idpgroup#member -> model by UUID
		{
			input: tuple{"idpgroup-test-idpgroup#member", "writer", "model-" + model.UUID.String},
			want: createTuple(
				"idpgroup:test-idpgroup#member",
				"writer",
				"model:"+model.UUID.String,
			),
			err:         false,
			changesType: "model",
		},
		// Test idpgroup#member -> applicationoffer by name
		{
			input: tuple{"idpgroup-test-idpgroup#member", "consumer", "applicationoffer-" + offer.URL},
			want: createTuple(
				"idpgroup:test-idpgroup#member",
				"consumer",
				"applicationoffer:"+offer.UUID,
			),
			err:         false,
			changesType: "applicationoffer",
		},
		// Test idpgroup#member -> applicationoffer by UUID
		{
			input: tuple{"idpgroup-test-idpgroup#member", "consumer", "applicationoffer-" + offer.UUID},
			want: createTuple(
				"idpgroup:test-idpgroup#member",
				"consumer",
				"applicationoffer:"+offer.UUID,
			),
			err:         false,
			changesType: "applicationoffer",
		},
	}

	for i, tc := range tagTests {
		c.Logf("running test %d", i)
		if i != 0 {
			// Needed due to removing original added relations for this test.
			// Without, we cannot add the relations.
			//
			//nolint:errcheck
			s.COFGAClient.RemoveRelation(ctx, tc.want)
		}
		err := client.AddRelation(t.Context(), &apiparams.AddRelationRequest{
			Tuples: []apiparams.RelationshipTuple{
				{
					Object:       tc.input.object,
					Relation:     tc.input.relation,
					TargetObject: tc.input.target,
				},
			},
		})
		if tc.err {
			c.Assert(err, qt.Not(qt.IsNil))
			c.Assert(err, qt.ErrorMatches, tc.want)
		} else {
			c.Assert(err, qt.IsNil)
			changes, err := s.COFGAClient.ReadChanges(ctx, tc.changesType, 99, "")
			c.Assert(err, qt.IsNil)
			key := changes.GetChanges()[len(changes.GetChanges())-1].GetTupleKey()
			c.Assert(key.User, qt.DeepEquals, tc.want.Object.String())
			c.Assert(key.Relation, qt.DeepEquals, tc.want.Relation.String())
			c.Assert(key.Object, qt.DeepEquals, tc.want.Target.String())
		}
	}
}

// TestRemoveRelation currently verifies the following test cases,
// similar to the TestAddRelation but instead we add the relations and then
// remove them.
// When new relation control is to be added, please update this comment:
// user -> controller (name)
// user -> controller (uuid)
// user -> model (name)
// user -> model (uuid)
// user -> applicationoffer (name)
// user -> applicationoffer (uuid)
func TestRemoveRelation(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	ctx := t.Context()

	user, controller, model, offer, _, _, client, closeClient := createTestControllerEnvironment(c, s)
	defer closeClient()

	type tuple struct {
		user     string
		relation string
		object   string
	}
	type tagTest struct {
		toAdd       openfga.Tuple
		toRemove    tuple
		want        openfga.Tuple
		err         bool
		changesType string
	}

	tagTests := []tagTest{
		// Test user -> controller by name
		{
			toAdd: openfga.Tuple{
				Object:   ofganames.ConvertTag(user.ResourceTag()),
				Relation: "administrator",
				Target:   ofganames.ConvertTag(controller.ResourceTag()),
			},
			toRemove: tuple{"user-" + user.Name, "administrator", "controller-" + controller.Name},
			want: createTuple(
				"user:"+user.Name,
				"administrator",
				"controller:"+controller.UUID,
			),
			err:         false,
			changesType: "controller",
		},
		// Test user -> controller by UUID
		{
			toAdd: openfga.Tuple{
				Object:   ofganames.ConvertTag(user.ResourceTag()),
				Relation: "administrator",
				Target:   ofganames.ConvertTag(controller.ResourceTag()),
			},
			toRemove: tuple{"user-" + user.Name, "administrator", "controller-" + controller.UUID},
			want: createTuple(
				"user:"+user.Name,
				"administrator",
				"controller:"+controller.UUID,
			),
			err:         false,
			changesType: "controller",
		},
		// Test user -> model by name
		{
			toAdd: openfga.Tuple{
				Object:   ofganames.ConvertTag(user.ResourceTag()),
				Relation: "writer",
				Target:   ofganames.ConvertTag(model.ResourceTag()),
			},
			toRemove: tuple{"user-" + user.Name, "writer", "model-" + user.Name + "/" + model.Name},
			want: createTuple(
				"user:"+user.Name,
				"writer",
				"model:"+model.UUID.String,
			),
			err:         false,
			changesType: "model",
		},
		// Test user -> model by UUID
		{
			toAdd: openfga.Tuple{
				Object:   ofganames.ConvertTag(user.ResourceTag()),
				Relation: "writer",
				Target:   ofganames.ConvertTag(model.ResourceTag()),
			},
			toRemove: tuple{"user-" + user.Name, "writer", "model-" + model.UUID.String},
			want: createTuple(
				"user:"+user.Name,
				"writer",
				"model:"+model.UUID.String,
			),
			err:         false,
			changesType: "model",
		},
		// Test user -> applicationoffer by name
		{
			toAdd: openfga.Tuple{
				Object:   ofganames.ConvertTag(user.ResourceTag()),
				Relation: "consumer",
				Target:   ofganames.ConvertTag(offer.ResourceTag()),
			},
			toRemove: tuple{"user-" + user.Name, "consumer", "applicationoffer-" + offer.URL},
			want: createTuple(
				"user:"+user.Name,
				"consumer",
				"applicationoffer:"+offer.UUID,
			),
			err:         false,
			changesType: "applicationoffer",
		},
		// Test user -> applicationoffer by UUID
		{
			toAdd: openfga.Tuple{
				Object:   ofganames.ConvertTag(user.ResourceTag()),
				Relation: "consumer",
				Target:   ofganames.ConvertTag(offer.ResourceTag()),
			},
			toRemove: tuple{"user-" + user.Name, "consumer", "applicationoffer-" + offer.UUID},
			want: createTuple(
				"user:"+user.Name,
				"consumer",
				"applicationoffer:"+offer.UUID,
			),
			err:         false,
			changesType: "applicationoffer",
		},
		// Test user -> idpgroup
		{
			toAdd: openfga.Tuple{
				Object:   ofganames.ConvertTag(user.ResourceTag()),
				Relation: ofganames.MemberRelation,
				Target:   ofganames.ConvertTag(jimmnames.NewIdPGroupTag("test-idpgroup")),
			},
			toRemove: tuple{"user-" + user.Name, "member", "idpgroup-test-idpgroup"},
			want: createTuple(
				"user:"+user.Name,
				"member",
				"idpgroup:test-idpgroup",
			),
			err:         false,
			changesType: "idpgroup",
		},
		// Test idpgroup#member -> controller by name
		{
			toAdd: openfga.Tuple{
				Object:   ofganames.ConvertTagWithRelation(jimmnames.NewIdPGroupTag("test-idpgroup"), ofganames.MemberRelation),
				Relation: "administrator",
				Target:   ofganames.ConvertTag(controller.ResourceTag()),
			},
			toRemove: tuple{"idpgroup-test-idpgroup#member", "administrator", "controller-" + controller.Name},
			want: createTuple(
				"idpgroup:test-idpgroup#member",
				"administrator",
				"controller:"+controller.UUID,
			),
			err:         false,
			changesType: "controller",
		},
		// Test idpgroup#member -> controller by UUID
		{
			toAdd: openfga.Tuple{
				Object:   ofganames.ConvertTagWithRelation(jimmnames.NewIdPGroupTag("test-idpgroup"), ofganames.MemberRelation),
				Relation: "administrator",
				Target:   ofganames.ConvertTag(controller.ResourceTag()),
			},
			toRemove: tuple{"idpgroup-test-idpgroup#member", "administrator", "controller-" + controller.UUID},
			want: createTuple(
				"idpgroup:test-idpgroup#member",
				"administrator",
				"controller:"+controller.UUID,
			),
			err:         false,
			changesType: "controller",
		},
		// Test idpgroup#member -> model by name
		{
			toAdd: openfga.Tuple{
				Object:   ofganames.ConvertTagWithRelation(jimmnames.NewIdPGroupTag("test-idpgroup"), ofganames.MemberRelation),
				Relation: "writer",
				Target:   ofganames.ConvertTag(model.ResourceTag()),
			},
			toRemove: tuple{"idpgroup-test-idpgroup#member", "writer", "model-" + user.Name + "/" + model.Name},
			want: createTuple(
				"idpgroup:test-idpgroup#member",
				"writer",
				"model:"+model.UUID.String,
			),
			err:         false,
			changesType: "model",
		},
		// Test idpgroup#member -> model by UUID
		{
			toAdd: openfga.Tuple{
				Object:   ofganames.ConvertTagWithRelation(jimmnames.NewIdPGroupTag("test-idpgroup"), ofganames.MemberRelation),
				Relation: "writer",
				Target:   ofganames.ConvertTag(model.ResourceTag()),
			},
			toRemove: tuple{"idpgroup-test-idpgroup#member", "writer", "model-" + model.UUID.String},
			want: createTuple(
				"idpgroup:test-idpgroup#member",
				"writer",
				"model:"+model.UUID.String,
			),
			err:         false,
			changesType: "model",
		},
		// Test idpgroup#member -> applicationoffer by name
		{
			toAdd: openfga.Tuple{
				Object:   ofganames.ConvertTagWithRelation(jimmnames.NewIdPGroupTag("test-idpgroup"), ofganames.MemberRelation),
				Relation: "consumer",
				Target:   ofganames.ConvertTag(offer.ResourceTag()),
			},
			toRemove: tuple{"idpgroup-test-idpgroup#member", "consumer", "applicationoffer-" + offer.URL},
			want: createTuple(
				"idpgroup:test-idpgroup#member",
				"consumer",
				"applicationoffer:"+offer.UUID,
			),
			err:         false,
			changesType: "applicationoffer",
		},
		// Test idpgroup#member -> applicationoffer by UUID
		{
			toAdd: openfga.Tuple{
				Object:   ofganames.ConvertTagWithRelation(jimmnames.NewIdPGroupTag("test-idpgroup"), ofganames.MemberRelation),
				Relation: "consumer",
				Target:   ofganames.ConvertTag(offer.ResourceTag()),
			},
			toRemove: tuple{"idpgroup-test-idpgroup#member", "consumer", "applicationoffer-" + offer.UUID},
			want: createTuple(
				"idpgroup:test-idpgroup#member",
				"consumer",
				"applicationoffer:"+offer.UUID,
			),
			err:         false,
			changesType: "applicationoffer",
		},
	}

	for i, tc := range tagTests {
		c.Logf("running test %d", i)
		ofgaClient := s.JIMM.OpenFGAClient
		err := ofgaClient.AddRelation(t.Context(), tc.toAdd)
		c.Check(err, qt.IsNil)
		changes, err := s.COFGAClient.ReadChanges(ctx, tc.changesType, 99, "")
		c.Assert(err, qt.IsNil)
		key := changes.GetChanges()[len(changes.GetChanges())-1].GetTupleKey()
		c.Assert(key.User, qt.DeepEquals, tc.want.Object.String())
		c.Assert(key.Relation, qt.DeepEquals, tc.want.Relation.String())
		c.Assert(key.Object, qt.DeepEquals, tc.want.Target.String())

		err = client.RemoveRelation(t.Context(), &apiparams.RemoveRelationRequest{
			Tuples: []apiparams.RelationshipTuple{
				{
					Object:       tc.toRemove.user,
					Relation:     tc.toRemove.relation,
					TargetObject: tc.toRemove.object,
				},
			},
		})
		if tc.err {
			c.Assert(err, qt.Not(qt.IsNil))
			c.Assert(err, qt.ErrorMatches, tc.want)
		} else {
			c.Assert(err, qt.IsNil)
			changes, err := s.COFGAClient.ReadChanges(ctx, tc.changesType, 99, "")
			c.Assert(err, qt.IsNil)
			change := changes.GetChanges()[len(changes.GetChanges())-1]
			operation := change.GetOperation()
			c.Assert(string(operation), qt.Equals, "TUPLE_OPERATION_DELETE")
			key := change.GetTupleKey()
			c.Assert(key.User, qt.DeepEquals, tc.want.Object.String())
			c.Assert(key.Relation, qt.DeepEquals, tc.want.Relation.String())
			c.Assert(key.Object, qt.DeepEquals, tc.want.Target.String())
		}
	}
}

func TestListRelationshipTuples(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	user, controller, _, applicationOffer, _, _, client, closeClient := createTestControllerEnvironment(c, s)
	defer closeClient()

	response, err := client.ListRelationshipTuples(t.Context(), &apiparams.ListRelationshipTuplesRequest{ResolveUUIDs: true})
	c.Assert(err, qt.IsNil)
	initialTupleCount := len(response.Tuples)

	tuples := []apiparams.RelationshipTuple{{
		Object:       "user-" + user.Name,
		Relation:     "administrator",
		TargetObject: "controller-" + controller.Name,
	}, {
		Object:       "user-" + user.Name,
		Relation:     "administrator",
		TargetObject: "applicationoffer-" + applicationOffer.URL,
	}, {
		Object:       "user-" + user.Name,
		Relation:     "member",
		TargetObject: "idpgroup-test-idpgroup",
	}, {
		Object:       "idpgroup-test-idpgroup#member",
		Relation:     "administrator",
		TargetObject: "controller-" + controller.Name,
	}}

	err = client.AddRelation(t.Context(), &apiparams.AddRelationRequest{Tuples: tuples})
	c.Assert(err, qt.IsNil)

	response, err = client.ListRelationshipTuples(t.Context(), &apiparams.ListRelationshipTuplesRequest{ResolveUUIDs: true})
	c.Assert(err, qt.IsNil)
	// first tuples are created during setup test
	c.Assert(response.Tuples[initialTupleCount:], qt.DeepEquals, tuples)
	if len(response.Errors) != 0 {
		c.Logf("Errors: %+v", response.Errors)
	}
	c.Assert(len(response.Errors), qt.Equals, 0)

	response, err = client.ListRelationshipTuples(t.Context(), &apiparams.ListRelationshipTuplesRequest{
		Tuple: apiparams.RelationshipTuple{
			TargetObject: "applicationoffer-" + applicationOffer.URL,
		},
		ResolveUUIDs: true,
	})
	c.Assert(err, qt.IsNil)
	c.Assert(response.Tuples, qt.DeepEquals, []apiparams.RelationshipTuple{tuples[1]})
	c.Assert(len(response.Errors), qt.Equals, 0)

	// Test error message when a resource is not found
	_, err = client.ListRelationshipTuples(t.Context(), &apiparams.ListRelationshipTuplesRequest{
		Tuple: apiparams.RelationshipTuple{
			TargetObject: "applicationoffer-" + "fake-offer",
		},
		ResolveUUIDs: true,
	})
	c.Assert(err, qt.ErrorMatches, "failed to list relations: failed to parse tuple target object key applicationoffer-fake-offer: application offer not found.*")
}

func TestListRelationshipTuplesNoUUIDResolution(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	_, _, _, applicationOffer, _, _, client, closeClient := createTestControllerEnvironment(c, s)
	defer closeClient()

	tuples := []apiparams.RelationshipTuple{{
		Object:       "idpgroup-test-idpgroup#member",
		Relation:     "administrator",
		TargetObject: "applicationoffer-" + applicationOffer.UUID,
	}}

	err := client.AddRelation(t.Context(), &apiparams.AddRelationRequest{Tuples: tuples})
	c.Assert(err, qt.IsNil)

	expected := []apiparams.RelationshipTuple{{
		Object:       "idpgroup-test-idpgroup#member",
		Relation:     "administrator",
		TargetObject: "applicationoffer-" + applicationOffer.UUID,
	}}
	response, err := client.ListRelationshipTuples(t.Context(), &apiparams.ListRelationshipTuplesRequest{
		Tuple: apiparams.RelationshipTuple{
			TargetObject: "applicationoffer-" + applicationOffer.URL,
		},
		ResolveUUIDs: false,
	})
	c.Assert(err, qt.IsNil)
	c.Assert(response.Tuples, qt.DeepEquals, expected)
	c.Assert(len(response.Errors), qt.Equals, 0)
}

func TestCheckRelationAsNonAdmin(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()
	client := api.NewClient(conn)

	userAliceKey := "user-alice@canonical.com"
	userBobKey := "user-bob@canonical.com"

	// Verify Bob checking for Alice's permission fails
	input := apiparams.RelationshipTuple{
		Object:       userAliceKey,
		Relation:     "administrator",
		TargetObject: "controller-jimm",
	}
	req := apiparams.CheckRelationRequest{Tuple: input}
	_, err := client.CheckRelation(t.Context(), &req)
	c.Assert(err, qt.ErrorMatches, `failed to check relation: unauthorized \(unauthorized access\)`)
	// Verify Bob can check for his own permission.
	input = apiparams.RelationshipTuple{
		Object:       userBobKey,
		Relation:     "administrator",
		TargetObject: "controller-jimm",
	}
	req = apiparams.CheckRelationRequest{Tuple: input}
	_, err = client.CheckRelation(t.Context(), &req)
	c.Assert(err, qt.IsNil)
}

func TestCheckRelationOfferReaderFlow(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	ctx := t.Context()
	ofgaClient := s.JIMM.OpenFGAClient

	user, _, _, offer, _, _, _, closeClient := createTestControllerEnvironment(c, s)
	defer closeClient()

	// Log in the user as a member of an IDP group so that permissions granted
	// to the group are inherited via contextual tuples.
	conn, err := s.OpenCustomLoginProvider(c, nil, user.Name, jimmtest.NewUserSessionLogin(c, user.Name, "offer-readers"))
	c.Assert(err, qt.IsNil)
	defer conn.Close()
	client := api.NewClient(conn)

	// Some tags (tuples) to assist in the creation of tuples within OpenFGA (such that they can be tested against)
	idpGroupTag := ofganames.ConvertTagWithRelation(jimmnames.NewIdPGroupTag("offer-readers"), ofganames.MemberRelation)
	offerTag := ofganames.ConvertTag(offer.ResourceTag())

	// JAAS style keys, to be translated and checked against UUIDs/users
	userJAASKey := "user-" + user.Name
	offerJAASKey := "applicationoffer-" + offer.URL

	// Grant the IDP group members reader access to the application offer.
	idpGroupToOfferReader := openfga.Tuple{
		Object:   idpGroupTag,
		Relation: "reader",
		Target:   offerTag,
	}

	err = ofgaClient.AddRelation(
		ctx,
		idpGroupToOfferReader,
	)
	c.Assert(err, qt.IsNil)

	type test struct {
		input apiparams.RelationshipTuple
		want  bool
	}

	tests := []test{

		// Test user-> reader -> aoffer (due to IDP group membership)
		{
			input: apiparams.RelationshipTuple{
				Object:       userJAASKey,
				Relation:     "reader",
				TargetObject: offerJAASKey,
			},
			want: true,
		},
		// Test user -> consumer -> offer (FAILS as there is no union or direct relation to consumer)
		{
			input: apiparams.RelationshipTuple{
				Object:       userJAASKey,
				Relation:     "consumer",
				TargetObject: offerJAASKey,
			},
			want: false,
		},
	}

	for _, tc := range tests {
		req := apiparams.CheckRelationRequest{Tuple: tc.input}
		res, err := client.CheckRelation(t.Context(), &req)
		c.Assert(err, qt.IsNil)
		c.Assert(res.Allowed, qt.Equals, tc.want)
	}
}

func TestCheckRelationOfferConsumerFlow(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	ctx := t.Context()
	ofgaClient := s.JIMM.OpenFGAClient

	user, _, _, offer, _, _, _, closeClient := createTestControllerEnvironment(c, s)
	defer closeClient()

	// Log in the user as a member of an IDP group so that permissions granted
	// to the group are inherited via contextual tuples.
	conn, err := s.OpenCustomLoginProvider(c, nil, user.Name, jimmtest.NewUserSessionLogin(c, user.Name, "offer-consumers"))
	c.Assert(err, qt.IsNil)
	defer conn.Close()
	client := api.NewClient(conn)

	// Some keys to assist in the creation of tuples within OpenFGA (such that they can be tested against)
	idpGroupTag := ofganames.ConvertTagWithRelation(jimmnames.NewIdPGroupTag("offer-consumers"), ofganames.MemberRelation)
	offerTag := ofganames.ConvertTag(offer.ResourceTag())

	// JAAS style keys, to be translated and checked against UUIDs/users
	userJAASKey := "user-" + user.Name
	offerJAASKey := "applicationoffer-" + offer.URL

	// Grant the IDP group members consumer access to the application offer.
	idpGroupToOfferConsumer := openfga.Tuple{
		Object:   idpGroupTag,
		Relation: "consumer",
		Target:   offerTag,
	}

	err = ofgaClient.AddRelation(
		ctx,
		idpGroupToOfferConsumer,
	)
	c.Assert(err, qt.IsNil)

	type test struct {
		input apiparams.RelationshipTuple
		want  bool
	}

	tests := []test{
		// Test user -> consumer -> offer (due to IDP group membership)
		{
			input: apiparams.RelationshipTuple{
				Object:       userJAASKey,
				Relation:     "consumer",
				TargetObject: offerJAASKey,
			},
			want: true,
		},
		// Test user -> reader -> offer (due to union from consumer to reader)
		{
			input: apiparams.RelationshipTuple{
				Object:       userJAASKey,
				Relation:     "reader",
				TargetObject: offerJAASKey,
			},
			want: true,
		},
	}

	for _, tc := range tests {
		req := apiparams.CheckRelationRequest{Tuple: tc.input}
		res, err := client.CheckRelation(t.Context(), &req)
		c.Assert(err, qt.IsNil)
		c.Assert(res.Allowed, qt.Equals, tc.want)
	}
}

func TestCheckRelationModelReaderFlow(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	ctx := t.Context()
	ofgaClient := s.JIMM.OpenFGAClient

	user, _, model, _, _, _, _, closeClient := createTestControllerEnvironment(c, s)
	defer closeClient()

	// Log in the user as a member of an IDP group so that permissions granted
	// to the group are inherited via contextual tuples.
	conn, err := s.OpenCustomLoginProvider(c, nil, user.Name, jimmtest.NewUserSessionLogin(c, user.Name, "model-readers"))
	c.Assert(err, qt.IsNil)
	defer conn.Close()
	client := api.NewClient(conn)

	// Some tags (tuples) to assist in the creation of tuples within OpenFGA (such that they can be tested against)
	idpGroupTag := ofganames.ConvertTagWithRelation(jimmnames.NewIdPGroupTag("model-readers"), ofganames.MemberRelation)
	modelTag := ofganames.ConvertTag(model.ResourceTag())

	// JAAS style keys, to be translated and checked against UUIDs/users
	userJAASKey := "user-" + user.Name
	modelJAASKey := "model-" + user.Name + "/" + model.Name

	// Grant the IDP group members reader access to the model.
	idpGroupToModelReader := openfga.Tuple{
		Object:   idpGroupTag,
		Relation: "reader",
		Target:   modelTag,
	}

	err = ofgaClient.AddRelation(
		ctx,
		idpGroupToModelReader,
	)
	c.Assert(err, qt.IsNil)

	type test struct {
		input apiparams.RelationshipTuple
		want  bool
	}

	tests := []test{
		// Test user -> reader -> model (due to IDP group membership)
		{
			input: apiparams.RelationshipTuple{
				Object:       userJAASKey,
				Relation:     "reader",
				TargetObject: modelJAASKey,
			},
			want: true,
		},
		// Test user -> writer -> model (FAILS as there is no union or direct relation to writer)
		{
			input: apiparams.RelationshipTuple{
				Object:       userJAASKey,
				Relation:     "writer",
				TargetObject: modelJAASKey,
			},
			want: false,
		},
	}

	for _, tc := range tests {
		req := apiparams.CheckRelationRequest{Tuple: tc.input}
		res, err := client.CheckRelation(t.Context(), &req)
		c.Assert(err, qt.IsNil)
		c.Assert(res.Allowed, qt.Equals, tc.want)
	}
}

func TestCheckRelationModelWriterFlow(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	ctx := t.Context()
	ofgaClient := s.JIMM.OpenFGAClient

	user, _, model, _, _, _, _, closeClient := createTestControllerEnvironment(c, s)
	defer closeClient()

	// Log in the user as a member of an IDP group so that permissions granted
	// to the group are inherited via contextual tuples.
	conn, err := s.OpenCustomLoginProvider(c, nil, user.Name, jimmtest.NewUserSessionLogin(c, user.Name, "model-writers"))
	c.Assert(err, qt.IsNil)
	defer conn.Close()
	client := api.NewClient(conn)

	// Some keys to assist in the creation of tuples within OpenFGA (such that they can be tested against)
	idpGroupTag := ofganames.ConvertTagWithRelation(jimmnames.NewIdPGroupTag("model-writers"), ofganames.MemberRelation)
	modelTag := ofganames.ConvertTag(model.ResourceTag())

	// Grant the IDP group members writer access to the model.
	idpGroupToModelWriter := openfga.Tuple{
		Object:   idpGroupTag,
		Relation: "writer",
		Target:   modelTag,
	}

	// JAAS style keys, to be translated and checked against UUIDs/users
	userJAASKey := "user-" + user.Name
	modelJAASKey := "model-" + user.Name + "/" + model.Name

	err = ofgaClient.AddRelation(
		ctx,
		idpGroupToModelWriter,
	)
	c.Assert(err, qt.IsNil)

	type test struct {
		input apiparams.RelationshipTuple
		want  bool
	}

	tests := []test{
		// Test user-> writer -> model (due to IDP group membership)
		{
			input: apiparams.RelationshipTuple{
				Object:       userJAASKey,
				Relation:     "writer",
				TargetObject: modelJAASKey,
			},
			want: true,
		},
		// Test user-> reader -> model(due to union from writer to reader)
		{
			input: apiparams.RelationshipTuple{
				Object:       userJAASKey,
				Relation:     "reader",
				TargetObject: modelJAASKey,
			},
			want: true,
		},
	}

	for _, tc := range tests {
		req := apiparams.CheckRelationRequest{Tuple: tc.input}
		res, err := client.CheckRelation(t.Context(), &req)
		c.Assert(err, qt.IsNil)
		c.Assert(res.Allowed, qt.Equals, tc.want)
	}
}

func TestCheckRelationControllerAdministratorFlow(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	ctx := t.Context()
	ofgaClient := s.JIMM.OpenFGAClient

	user, controller, model, offer, _, _, _, closeClient := createTestControllerEnvironment(c, s)
	defer closeClient()

	// Log in the user as a member of an IDP group so that permissions granted
	// to the group are inherited via contextual tuples.
	conn, err := s.OpenCustomLoginProvider(c, nil, user.Name, jimmtest.NewUserSessionLogin(c, user.Name, "controller-admins"))
	c.Assert(err, qt.IsNil)
	defer conn.Close()
	client := api.NewClient(conn)

	// Some keys to assist in the creation of tuples within OpenFGA (such that they can be tested against)
	idpGroupTag := ofganames.ConvertTagWithRelation(jimmnames.NewIdPGroupTag("controller-admins"), ofganames.MemberRelation)
	modelTag := ofganames.ConvertTag(model.ResourceTag())
	controllerTag := ofganames.ConvertTag(controller.ResourceTag())
	offerTag := ofganames.ConvertTag(offer.ResourceTag())

	// JAAS style keys, to be translated and checked against UUIDs/users
	userJAASKey := "user-" + user.Name
	controllerJAASKey := "controller-" + controller.Name
	modelJAASKey := "model-" + user.Name + "/" + model.Name
	offerJAASKey := "applicationoffer-" + offer.URL

	// Test the administrator flow of a user being related to a controller via administrator relation
	// through IDP group membership.
	idpGroupToControllerAdmin := openfga.Tuple{
		Object:   idpGroupTag,
		Relation: "administrator",
		Target:   controllerTag,
	}

	// NOTE (alesstimec) these two shouldn't really be necessary as they should be automatically
	// created.
	controllerToModelAdmin := openfga.Tuple{
		Object:   controllerTag,
		Relation: "controller",
		Target:   modelTag,
	} // Make controller administrators admins of model via administrator union
	modelToAppOfferAdmin := openfga.Tuple{
		Object:   modelTag,
		Relation: "model",
		Target:   offerTag,
	} // Make controller administrators admin of appoffers via administrator union

	err = ofgaClient.AddRelation(
		ctx,
		idpGroupToControllerAdmin,
		controllerToModelAdmin,
		modelToAppOfferAdmin,
	)
	c.Assert(err, qt.IsNil)

	type test struct {
		input apiparams.RelationshipTuple
		want  bool
	}

	tests := []test{
		// Test user-> administrator -> controller (due to IDP group membership)
		{
			input: apiparams.RelationshipTuple{
				Object:       userJAASKey,
				Relation:     "administrator",
				TargetObject: controllerJAASKey,
			},
			want: true,
		},
		// Test user-> administrator -> model
		{
			input: apiparams.RelationshipTuple{
				Object:       userJAASKey,
				Relation:     "administrator",
				TargetObject: modelJAASKey,
			},
			want: true,
		},
		// Test user -> reader -> model (due to controller#admin unioned to model #admin)
		{
			input: apiparams.RelationshipTuple{
				Object:       userJAASKey,
				Relation:     "reader",
				TargetObject: modelJAASKey,
			},
			want: true,
		},
		// Test user-> writer -> model (due to controller#admin unioned to model #admin)
		{
			input: apiparams.RelationshipTuple{
				Object:       userJAASKey,
				Relation:     "writer",
				TargetObject: modelJAASKey,
			},
			want: true,
		},
		// Test user -> administrator -> offer
		{
			input: apiparams.RelationshipTuple{
				Object:       userJAASKey,
				Relation:     "administrator",
				TargetObject: offerJAASKey,
			},
			want: true,
		},
	}

	for _, tc := range tests {
		req := apiparams.CheckRelationRequest{Tuple: tc.input}
		res, err := client.CheckRelation(t.Context(), &req)
		c.Assert(err, qt.IsNil)
		c.Assert(res.Allowed, qt.Equals, tc.want)
	}
	// Check that the same tuples can be checked via the CheckRelations API
	tuplesToCheck := apiparams.CheckRelationsRequest{}
	expected := apiparams.CheckRelationsResponse{}
	for _, tc := range tests {
		tuplesToCheck.Tuples = append(tuplesToCheck.Tuples, tc.input)
		expected.Results = append(expected.Results, apiparams.CheckRelationResponse{
			Allowed: tc.want,
		})
	}
	results, err := client.CheckRelations(t.Context(), &tuplesToCheck)
	c.Assert(err, qt.IsNil)
	c.Assert(results, qt.DeepEquals, expected)
}

/*
 None-facade related tests
*/

func TestModifyModelAccessDowngradesUserToNoAccess(t *testing.T) {
	c := qt.New(t)
	revoke, charlieAccess, charlieClient, modelTag := setupModelWithCharlieAsAdmin(c)

	c.Assert(charlieAccess(), qt.Equals, "admin")

	revoke(jujuparams.ModelAdminAccess)
	c.Assert(charlieAccess(), qt.Equals, "write")

	revoke(jujuparams.ModelWriteAccess)
	c.Assert(charlieAccess(), qt.Equals, "read")

	revoke(jujuparams.ModelReadAccess)
	c.Assert(charlieAccess(), qt.Equals, "")

	charlieInfo, err := charlieClient.ModelInfo(t.Context(), []names.ModelTag{modelTag})
	c.Assert(err, qt.IsNil)
	c.Assert(charlieInfo, qt.HasLen, 1)
	c.Assert(charlieInfo[0].Error, qt.Not(qt.IsNil))
	c.Assert(charlieInfo[0].Error.Code, qt.Equals, jujuparams.CodeUnauthorized)
}

// TestModifyModelAccessRevocationCascadesToReader tests that the "writer" permission is removed from an "admin",
// then a "reader" is left. This matches Juju behaviour.
func TestModifyModelAccessRevocationCascadesToReader(t *testing.T) {
	c := qt.New(t)
	revoke, charlieAccess, charlieClient, modelTag := setupModelWithCharlieAsAdmin(c)

	c.Assert(charlieAccess(), qt.Equals, "admin")

	revoke(jujuparams.ModelWriteAccess)
	c.Assert(charlieAccess(), qt.Equals, "read")

	revoke(jujuparams.ModelReadAccess)
	c.Assert(charlieAccess(), qt.Equals, "")

	charlieInfo, err := charlieClient.ModelInfo(t.Context(), []names.ModelTag{modelTag})
	c.Assert(err, qt.IsNil)
	c.Assert(charlieInfo, qt.HasLen, 1)
	c.Assert(charlieInfo[0].Error, qt.Not(qt.IsNil))
	c.Assert(charlieInfo[0].Error.Code, qt.Equals, jujuparams.CodeUnauthorized)
}

func setupModelWithCharlieAsAdmin(c *qt.C) (func(jujuparams.UserAccessPermission), func() string, *modelmanager.Client, names.ModelTag) {
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	connBob := s.Open(c, nil, "bob@canonical.com", nil)
	bobClient := modelmanager.NewClient(connBob)

	connCharlie := s.Open(c, nil, "charlie@canonical.com", nil)
	charlieClient := modelmanager.NewClient(connCharlie)

	c.Cleanup(func() {
		connBob.Close()
		connCharlie.Close()
	})

	modelTag := names.NewModelTag(model.UUID.String)

	err := bobClient.GrantModel(c.Context(), "charlie@canonical.com", "admin", model.UUID.String)
	c.Assert(err, qt.IsNil)

	charlieAccess := func() string {
		info, err := bobClient.ModelInfo(c.Context(), []names.ModelTag{modelTag})
		c.Assert(err, qt.IsNil)
		c.Assert(info, qt.HasLen, 1)
		c.Assert(info[0].Error, qt.Equals, (*jujuparams.Error)(nil))
		for _, userInfo := range info[0].Result.Users {
			if userInfo.UserName == "charlie@canonical.com" {
				return string(userInfo.Access)
			}
		}
		return ""
	}

	revoke := func(access jujuparams.UserAccessPermission) {
		connBob := s.Open(c, nil, "bob@canonical.com", nil)
		bobClient := modelmanager.NewClient(connBob)
		err := bobClient.RevokeModel(c.Context(), "charlie@canonical.com", string(access), model.UUID.String)
		c.Assert(err, qt.IsNil)
	}

	return revoke, charlieAccess, charlieClient, modelTag
}

// createTestControllerEnvironment is a utility function creating the necessary components of adding a:
//   - user
//   - controller
//   - model
//   - application offer
//   - cloud
//   - cloud credential
//
// Into the test database, returning the dbmodels to be utilised for values within tests.
//
// It returns all of the latter, but in addition to those, also:
//   - an api client to make calls to an httptest instance of the server
//   - a closure containing a function to close the connection
func createTestControllerEnvironment(c *qt.C, s jimmtest.JimmWithControllers) (
	dbmodel.Identity,
	dbmodel.Controller,
	dbmodel.Model,
	dbmodel.ApplicationOffer,
	dbmodel.Cloud,
	dbmodel.CloudCredential,
	*api.Client,
	func()) {
	ctx := c.Context()

	db := s.JIMM.Database

	u, err := dbmodel.NewIdentity(petname.Generate(2, "-") + "@canonical.com")
	c.Assert(err, qt.IsNil)

	c.Assert(db.DB.Create(u).Error, qt.IsNil)

	cloud := dbmodel.Cloud{
		Name: petname.Generate(2, "-"),
		Type: "aws",
		Regions: []dbmodel.CloudRegion{{
			Name: petname.Generate(2, "-"),
		}},
	}
	c.Assert(db.DB.Create(&cloud).Error, qt.IsNil)
	id, _ := uuid.NewRandom()
	controller := dbmodel.Controller{
		Name:        petname.Generate(2, "-"),
		UUID:        id.String(),
		CloudName:   cloud.Name,
		CloudRegion: cloud.Regions[0].Name,
		CloudRegions: []dbmodel.CloudRegionControllerPriority{{
			Priority:      0,
			CloudRegionID: cloud.Regions[0].ID,
		}},
	}
	err = db.AddController(ctx, &controller)
	c.Assert(err, qt.IsNil)

	cred := dbmodel.CloudCredential{
		Name:              petname.Generate(2, "-"),
		CloudName:         cloud.Name,
		OwnerIdentityName: u.Name,
		AuthType:          "empty",
	}
	err = db.SetCloudCredential(ctx, &cred)
	c.Assert(err, qt.IsNil)

	model := dbmodel.Model{
		Name: petname.Generate(2, "-"),
		UUID: sql.NullString{
			String: id.String(),
			Valid:  true,
		},
		OwnerIdentityName: u.Name,
		ControllerID:      controller.ID,
		CloudRegionID:     cloud.Regions[0].ID,
		CloudCredentialID: cred.ID,
		Life:              string(life.Alive),
	}

	err = db.AddModel(ctx, &model)
	c.Assert(err, qt.IsNil)

	offerName := petname.Generate(2, "-")
	offerURL, err := crossmodel.ParseOfferURL(controller.Name + ":" + u.Name + "/" + model.Name + "." + offerName)
	c.Assert(err, qt.IsNil)

	offer := dbmodel.ApplicationOffer{
		UUID:    id.String(),
		Name:    offerName,
		ModelID: model.ID,
		URL:     offerURL.String(),
	}
	err = db.AddApplicationOffer(c.Context(), &offer)
	c.Assert(err, qt.IsNil)
	c.Assert(len(offer.UUID), qt.Equals, 36)

	conn := s.Open(c, nil, "alice@canonical.com", nil)
	client := api.NewClient(conn)

	return *u, controller, model, offer, cloud, cred, client, func() {
		conn.Close()
	}
}
