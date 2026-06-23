// Copyright 2026 Canonical.

package testing

import (
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	jujuparams "github.com/juju/juju/rpc/params"

	"github.com/canonical/jimm/v3/internal/testutils/jimmtest"
)

// These tests exercise the Controller facade version 12 (Juju 3.6) handlers end
// to end against a real backing controller, using hand-crafted version-pinned
// calls with conn.APICall and the juju 4.x "*Legacy" param structs (the 3.6
// owner-tag wire shapes).
//
// Unlike the ModelManager v10 CreateModel tests, the Controller v12 handlers
// covered here (AllModels, ModelStatus) are read operations: JIMM brokers them
// to the hosting controller and translates the result, so they work against a
// backing controller of any version and do not require a Juju 3.x controller.

// TestControllerV12AllModels checks the Controller v12 AllModels handler reports
// models in owner-tag form.
func TestControllerV12AllModels(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	conn := s.Open(c, nil, bobOwnerTag.Id(), nil)
	defer conn.Close()

	var list jujuparams.UserModelListLegacy
	err := conn.APICall(t.Context(), "Controller", 12, "", "AllModels", nil, &list)
	c.Assert(err, qt.IsNil)
	c.Assert(len(list.UserModels) > 0, qt.IsTrue)

	var found bool
	for _, um := range list.UserModels {
		// Every model must be reported in owner-tag form, never qualifier form.
		c.Check(strings.HasPrefix(um.OwnerTag, "user-"), qt.IsTrue, qt.Commentf("owner tag %q", um.OwnerTag))
		if um.UUID == model.UUID.String {
			found = true
			c.Check(um.OwnerTag, qt.Equals, bobOwnerTag.String())
			c.Check(um.Name, qt.Equals, model.Name)
		}
	}
	c.Assert(found, qt.IsTrue)
}

// TestControllerV12ModelStatus checks the Controller v12 ModelStatus handler
// reports owner tags, with a per-result error for a malformed tag.
func TestControllerV12ModelStatus(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)
	model := s.CreateModelForBob(c)

	conn := s.Open(c, nil, bobOwnerTag.Id(), nil)
	defer conn.Close()

	args := jujuparams.Entities{Entities: []jujuparams.Entity{
		{Tag: model.ResourceTag().String()},
		{Tag: "invalid-model-tag"},
	}}

	var res jujuparams.ModelStatusResultsLegacy
	err := conn.APICall(t.Context(), "Controller", 12, "", "ModelStatus", args, &res)
	c.Assert(err, qt.IsNil)
	c.Assert(res.Results, qt.HasLen, 2)

	c.Check(res.Results[0].OwnerTag, qt.Equals, bobOwnerTag.String())
	c.Check(res.Results[0].Error == nil, qt.IsTrue)

	c.Check(res.Results[1].OwnerTag, qt.Equals, "")
	c.Check(res.Results[1].Error != nil, qt.IsTrue)
}
