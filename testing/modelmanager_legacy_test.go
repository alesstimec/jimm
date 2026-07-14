// Copyright 2026 Canonical.

package testing

import (
	"strings"
	"testing"

	petname "github.com/dustinkirkland/golang-petname"
	qt "github.com/frankban/quicktest"
	jujuparams "github.com/juju/juju/rpc/params"
	"github.com/juju/names/v6"

	"github.com/canonical/jimm/v3/internal/testutils/jimmtest"
)

// These tests exercise the ModelManager facade version 10 (Juju 3.6) handlers
// end to end against a real backing controller. A single Go module pins one
// Juju version (4.x), so we cannot import a 3.6 API client; instead we make
// hand-crafted version-pinned calls with conn.APICall and the juju 4.x
// "*Legacy" param structs, which are the 3.6 owner-tag wire shapes. This
// confirms a real JIMM advertises and dispatches v10 and that the owner-tag
// conversion holds on real controller data.

var bobOwnerTag = names.NewUserTag("bob@canonical.com")

// setupLegacyModelManagerTest sets up the JIMM e2e environment and skips the
// test unless a Juju 3.x backing controller is available. The 3.6-client
// (ModelManager version 10) handlers place new models on a controller of major
// version <= 3 (see JAAS-6), so these tests are only meaningful when the
// backing fleet includes such a controller.
func setupLegacyModelManagerTest(c *qt.C) jimmtest.JimmWithControllers {
	s := jimmtest.SetupJimmWithControllers(c)
	if !s.HasControllerWithMajorVersionAtMost(c, 3) {
		c.Skip("no Juju <=3.x backing controller available; 3.6-client ModelManager tests require one")
	}
	return s
}

// TestModelManagerV10CreateModel covers the v10 CreateModel handler: the
// owner-tag happy path, owner defaulting, authorization, duplicate names, and
// owner tags that cannot be converted to a qualifier.
func TestModelManagerV10CreateModel(t *testing.T) {
	c := qt.New(t)
	s := setupLegacyModelManagerTest(c)
	existing := s.CreateModelForBob(c)

	conn := s.OpenNoClientVersion(c, nil, bobOwnerTag.Id(), nil)
	defer conn.Close()

	cred := names.NewCloudCredentialTag(jimmtest.TestE2ECloudName + "/" + bobOwnerTag.Id() + "/cred")

	tests := []struct {
		about          string
		name           string
		ownerTag       string
		credentialTag  names.CloudCredentialTag
		expectError    string
		expectOwnerTag string // expected response owner tag for the success cases
	}{{
		about:          "success with explicit owner tag",
		name:           petname.Generate(2, "-"),
		ownerTag:       bobOwnerTag.String(),
		credentialTag:  cred,
		expectOwnerTag: bobOwnerTag.String(),
	}, {
		about:          "empty owner tag defaults to the authenticated user",
		name:           petname.Generate(2, "-"),
		ownerTag:       "",
		credentialTag:  cred,
		expectOwnerTag: bobOwnerTag.String(),
	}, {
		about:         "unauthorized for another user",
		name:          petname.Generate(2, "-"),
		ownerTag:      "user-noauthuser@canonical.com",
		credentialTag: cred,
		expectError:   `unauthorized \(unauthorized access\)`,
	}, {
		about:         "duplicate model name",
		name:          existing.Name,
		ownerTag:      bobOwnerTag.String(),
		credentialTag: cred,
		expectError:   "model " + bobOwnerTag.Id() + "/" + existing.Name + " already exists \\(already exists\\)",
	}, {
		about:       "owner tag is not a tag",
		name:        petname.Generate(2, "-"),
		ownerTag:    "not-a-tag",
		expectError: `.*is not a valid.*tag.*`,
	}, {
		about:       "owner tag is not a user",
		name:        petname.Generate(2, "-"),
		ownerTag:    "machine-0",
		expectError: `.*is not a valid.*tag.*`,
	}}

	for i, test := range tests {
		c.Logf("test %d. %s", i, test.about)

		args := jujuparams.ModelCreateArgsLegacy{
			Name:     test.name,
			OwnerTag: test.ownerTag,
			CloudTag: names.NewCloudTag(jimmtest.TestE2ECloudName).String(),
		}
		emptyCred := names.CloudCredentialTag{}
		if test.credentialTag != emptyCred {
			args.CloudCredentialTag = test.credentialTag.String()
		}

		var info jujuparams.ModelInfoLegacy
		err := conn.APICall(t.Context(), "ModelManager", 10, "", "CreateModel", args, &info)
		if test.expectError != "" {
			c.Check(err, qt.ErrorMatches, test.expectError)
			continue
		}
		c.Assert(err, qt.IsNil)
		c.Check(info.OwnerTag, qt.Equals, test.expectOwnerTag)
		c.Check(info.Name, qt.Equals, test.name)
		c.Check(info.UUID, qt.Not(qt.Equals), "")
	}
}

// TestModelManagerV10ModelInfo covers the v10 ModelInfo handler, which reports
// per-result errors: a valid model returns an owner tag, while an
// inaccessible or malformed tag becomes a result-level error.
func TestModelManagerV10ModelInfo(t *testing.T) {
	c := qt.New(t)
	s := setupLegacyModelManagerTest(c)
	model := s.CreateModelForBob(c)

	conn := s.OpenNoClientVersion(c, nil, bobOwnerTag.Id(), nil)
	defer conn.Close()

	args := jujuparams.Entities{Entities: []jujuparams.Entity{
		{Tag: model.ResourceTag().String()},
		// A well-formed but inaccessible model -> mapped to unauthorized.
		{Tag: names.NewModelTag("00000000-0000-0000-0000-0000000000ff").String()},
		// A malformed tag -> bad request.
		{Tag: "invalid-model-tag"},
	}}

	var res jujuparams.ModelInfoResultsLegacy
	err := conn.APICall(t.Context(), "ModelManager", 10, "", "ModelInfo", args, &res)
	c.Assert(err, qt.IsNil)
	c.Assert(res.Results, qt.HasLen, 3)

	c.Assert(res.Results[0].Result, qt.IsNotNil)
	c.Check(res.Results[0].Result.OwnerTag, qt.Equals, bobOwnerTag.String())
	c.Check(res.Results[0].Result.UUID, qt.Equals, model.UUID.String)
	c.Check(res.Results[0].Error == nil, qt.IsTrue)

	c.Check(res.Results[1].Result, qt.IsNil)
	c.Check(res.Results[1].Error != nil, qt.IsTrue)

	c.Check(res.Results[2].Result, qt.IsNil)
	c.Check(res.Results[2].Error != nil, qt.IsTrue)
}

// TestModelManagerV10ListModels checks the v10 ListModels handler reports every
// accessible model in owner-tag form.
func TestModelManagerV10ListModels(t *testing.T) {
	c := qt.New(t)
	s := setupLegacyModelManagerTest(c)
	model := s.CreateModelForBob(c)

	conn := s.OpenNoClientVersion(c, nil, bobOwnerTag.Id(), nil)
	defer conn.Close()

	var list jujuparams.UserModelListLegacy
	err := conn.APICall(t.Context(), "ModelManager", 10, "", "ListModels", jujuparams.Entity{}, &list)
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

// TestModelManagerV10ModelStatus covers the v10 ModelStatus handler, which
// reports per-result errors inline on each ModelStatus entry.
func TestModelManagerV10ModelStatus(t *testing.T) {
	c := qt.New(t)
	s := setupLegacyModelManagerTest(c)
	model := s.CreateModelForBob(c)

	conn := s.OpenNoClientVersion(c, nil, bobOwnerTag.Id(), nil)
	defer conn.Close()

	args := jujuparams.Entities{Entities: []jujuparams.Entity{
		{Tag: model.ResourceTag().String()},
		{Tag: "invalid-model-tag"},
	}}

	var res jujuparams.ModelStatusResultsLegacy
	err := conn.APICall(t.Context(), "ModelManager", 10, "", "ModelStatus", args, &res)
	c.Assert(err, qt.IsNil)
	c.Assert(res.Results, qt.HasLen, 2)

	c.Check(res.Results[0].OwnerTag, qt.Equals, bobOwnerTag.String())
	c.Check(res.Results[0].Error == nil, qt.IsTrue)

	c.Check(res.Results[1].OwnerTag, qt.Equals, "")
	c.Check(res.Results[1].Error != nil, qt.IsTrue)
}

// TestModelManagerV10ListModelSummaries checks the v10 ListModelSummaries
// handler reports summaries in owner-tag form.
func TestModelManagerV10ListModelSummaries(t *testing.T) {
	c := qt.New(t)
	s := setupLegacyModelManagerTest(c)
	model := s.CreateModelForBob(c)

	conn := s.OpenNoClientVersion(c, nil, bobOwnerTag.Id(), nil)
	defer conn.Close()

	var res jujuparams.ModelSummaryResultsLegacy
	err := conn.APICall(t.Context(), "ModelManager", 10, "", "ListModelSummaries", jujuparams.ModelSummariesRequest{}, &res)
	c.Assert(err, qt.IsNil)
	c.Assert(len(res.Results) > 0, qt.IsTrue)

	var found bool
	for _, r := range res.Results {
		if r.Result == nil {
			continue
		}
		c.Check(strings.HasPrefix(r.Result.OwnerTag, "user-"), qt.IsTrue, qt.Commentf("owner tag %q", r.Result.OwnerTag))
		if r.Result.UUID == model.UUID.String {
			found = true
			c.Check(r.Result.OwnerTag, qt.Equals, bobOwnerTag.String())
		}
	}
	c.Assert(found, qt.IsTrue)
}
