// Copyright 2026 Canonical.

package params36

import (
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/google/go-cmp/cmp"
	"github.com/juju/juju/core/crossmodel"
	"github.com/juju/juju/core/life"
	"github.com/juju/juju/core/semversion"
	jujuparams "github.com/juju/juju/rpc/params"

	"github.com/canonical/jimm/v3/internal/errors"
)

func TestOwnerTagQualifierRoundTrip(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		qualifier string
		ownerTag  string
	}{
		{qualifier: "alice@external", ownerTag: "user-alice@external"},
		{qualifier: "admin", ownerTag: "user-admin"},
		{qualifier: "bob@canonical.com", ownerTag: "user-bob@canonical.com"},
	}
	for _, test := range tests {
		ownerTag, err := qualifierToOwnerTag(test.qualifier)
		c.Assert(err, qt.IsNil)
		c.Check(ownerTag, qt.Equals, test.ownerTag)

		qualifier, err := ownerTagToQualifier(test.ownerTag)
		c.Assert(err, qt.IsNil)
		c.Check(qualifier, qt.Equals, test.qualifier)

		// The transform is an exact inverse for users.
		roundTripped, err := qualifierToOwnerTag(qualifier)
		c.Assert(err, qt.IsNil)
		c.Check(roundTripped, qt.Equals, test.ownerTag)
	}
}

func TestQualifierToOwnerTagInvalid(t *testing.T) {
	c := qt.New(t)

	for _, qualifier := range []string{"", "a b", "Not-A-User!"} {
		_, err := qualifierToOwnerTag(qualifier)
		c.Check(err, qt.IsNotNil, qt.Commentf("qualifier %q", qualifier))
		c.Check(errors.ErrorCode(err), qt.Equals, errors.CodeBadRequest)
	}
}

func TestOwnerTagToQualifierInvalid(t *testing.T) {
	c := qt.New(t)

	for _, ownerTag := range []string{"", "not-a-tag", "machine-0"} {
		_, err := ownerTagToQualifier(ownerTag)
		c.Check(err, qt.IsNotNil, qt.Commentf("owner tag %q", ownerTag))
	}
}

func TestModelCreateArgs(t *testing.T) {
	c := qt.New(t)

	in := jujuparams.ModelCreateArgsLegacy{
		Name:               "mymodel",
		OwnerTag:           "user-alice@external",
		Config:             map[string]any{"key": "value"},
		CloudTag:           "cloud-aws",
		CloudRegion:        "eu-west-1",
		CloudCredentialTag: "cloudcred-aws_alice@external_cred",
	}
	got, err := ModelCreateArgs(in)
	c.Assert(err, qt.IsNil)
	c.Check(got, qt.DeepEquals, jujuparams.ModelCreateArgs{
		Name:               "mymodel",
		Qualifier:          "alice@external",
		Config:             map[string]any{"key": "value"},
		CloudTag:           "cloud-aws",
		CloudRegion:        "eu-west-1",
		CloudCredentialTag: "cloudcred-aws_alice@external_cred",
	})

	// An empty owner tag yields an empty qualifier (owner defaults downstream).
	got, err = ModelCreateArgs(jujuparams.ModelCreateArgsLegacy{Name: "m"})
	c.Assert(err, qt.IsNil)
	c.Check(got.Qualifier, qt.Equals, "")

	// An invalid owner tag is an error.
	_, err = ModelCreateArgs(jujuparams.ModelCreateArgsLegacy{Name: "m", OwnerTag: "not-a-tag"})
	c.Check(err, qt.IsNotNil)
}

func TestLegacyModelInfo(t *testing.T) {
	c := qt.New(t)

	valid := true
	agentVersion := semversion.MustParse("4.0.0")
	in := jujuparams.ModelInfo{
		Name:                    "mymodel",
		Type:                    "iaas",
		UUID:                    "00000000-0000-0000-0000-000000000001",
		ControllerUUID:          "00000000-0000-0000-0000-0000000000ff",
		IsController:            false,
		ProviderType:            "ec2",
		CloudTag:                "cloud-aws",
		CloudRegion:             "eu-west-1",
		CloudCredentialTag:      "cloudcred-aws_alice@external_cred",
		CloudCredentialValidity: &valid,
		Qualifier:               "alice@external",
		Life:                    life.Alive,
		Status:                  jujuparams.EntityStatus{Status: "available"},
		AgentVersion:            &agentVersion,
		// TargetController has no legacy equivalent and must be dropped.
		TargetController: "controller-prod",
	}
	got, err := LegacyModelInfo(in)
	c.Assert(err, qt.IsNil)
	c.Check(got, qt.CmpEquals(cmp.AllowUnexported()), jujuparams.ModelInfoLegacy{
		Name:                    "mymodel",
		Type:                    "iaas",
		UUID:                    "00000000-0000-0000-0000-000000000001",
		ControllerUUID:          "00000000-0000-0000-0000-0000000000ff",
		IsController:            false,
		ProviderType:            "ec2",
		CloudTag:                "cloud-aws",
		CloudRegion:             "eu-west-1",
		CloudCredentialTag:      "cloudcred-aws_alice@external_cred",
		CloudCredentialValidity: &valid,
		OwnerTag:                "user-alice@external",
		Life:                    life.Alive,
		Status:                  jujuparams.EntityStatus{Status: "available"},
		AgentVersion:            &agentVersion,
	})

	// A non-user qualifier has no owner-tag representation.
	_, err = LegacyModelInfo(jujuparams.ModelInfo{Qualifier: "a b"})
	c.Check(err, qt.IsNotNil)
}

func TestLegacyModelInfoResults(t *testing.T) {
	c := qt.New(t)

	in := jujuparams.ModelInfoResults{
		Results: []jujuparams.ModelInfoResult{
			{Result: &jujuparams.ModelInfo{Name: "m1", Qualifier: "alice@external"}},
			{Error: &jujuparams.Error{Message: "boom", Code: "not found"}},
			{Result: &jujuparams.ModelInfo{Name: "m3", Qualifier: "a b"}},
		},
	}
	got := LegacyModelInfoResults(in)
	c.Assert(got.Results, qt.HasLen, 3)

	// Converted result.
	c.Assert(got.Results[0].Result, qt.IsNotNil)
	c.Check(got.Results[0].Result.OwnerTag, qt.Equals, "user-alice@external")
	c.Check(got.Results[0].Error == nil, qt.IsTrue)

	// Existing error is passed through untouched.
	c.Check(got.Results[1].Result, qt.IsNil)
	c.Check(got.Results[1].Error, qt.DeepEquals, &jujuparams.Error{Message: "boom", Code: "not found"})

	// Unconvertible qualifier becomes a result-level error, not a batch failure.
	c.Check(got.Results[2].Result, qt.IsNil)
	c.Check(got.Results[2].Error, qt.IsNotNil)
}

func TestLegacyUserModelList(t *testing.T) {
	c := qt.New(t)

	now := time.Unix(1700000000, 0).UTC()
	in := jujuparams.UserModelList{
		UserModels: []jujuparams.UserModel{{
			Model: jujuparams.Model{
				Name:      "mymodel",
				Qualifier: "alice@external",
				UUID:      "00000000-0000-0000-0000-000000000001",
				Type:      "iaas",
			},
			LastConnection: &now,
		}},
	}
	got, err := LegacyUserModelList(in)
	c.Assert(err, qt.IsNil)
	c.Assert(got.UserModels, qt.HasLen, 1)
	c.Check(got.UserModels[0].ModelLegacy, qt.DeepEquals, jujuparams.ModelLegacy{
		Name:     "mymodel",
		UUID:     "00000000-0000-0000-0000-000000000001",
		Type:     "iaas",
		OwnerTag: "user-alice@external",
	})
	c.Check(got.UserModels[0].LastConnection, qt.DeepEquals, &now)

	// A non-user qualifier fails the conversion (no per-item error slot).
	_, err = LegacyUserModelList(jujuparams.UserModelList{
		UserModels: []jujuparams.UserModel{{Model: jujuparams.Model{Qualifier: "a b"}}},
	})
	c.Check(err, qt.IsNotNil)
}

func TestLegacyModelStatusResults(t *testing.T) {
	c := qt.New(t)

	in := jujuparams.ModelStatusResults{
		Results: []jujuparams.ModelStatus{
			{ModelTag: "model-1", Qualifier: "alice@external", UnitCount: 3},
			{Error: &jujuparams.Error{Message: "boom"}},
			{ModelTag: "model-3", Qualifier: "a b"},
		},
	}
	got := LegacyModelStatusResults(in)
	c.Assert(got.Results, qt.HasLen, 3)

	// Converted.
	c.Check(got.Results[0].OwnerTag, qt.Equals, "user-alice@external")
	c.Check(got.Results[0].UnitCount, qt.Equals, 3)
	c.Check(got.Results[0].Error == nil, qt.IsTrue)

	// Existing error passes through; no qualifier conversion attempted.
	c.Check(got.Results[1].OwnerTag, qt.Equals, "")
	c.Check(got.Results[1].Error, qt.DeepEquals, &jujuparams.Error{Message: "boom"})

	// Unconvertible qualifier becomes the item's error.
	c.Check(got.Results[2].OwnerTag, qt.Equals, "")
	c.Check(got.Results[2].Error, qt.IsNotNil)
}

func TestLegacyModelSummaryResults(t *testing.T) {
	c := qt.New(t)

	in := jujuparams.ModelSummaryResults{
		Results: []jujuparams.ModelSummaryResult{
			{Result: &jujuparams.ModelSummary{Name: "m1", Qualifier: "alice@external"}},
			{Error: &jujuparams.Error{Message: "boom"}},
			{Result: &jujuparams.ModelSummary{Name: "m3", Qualifier: "a b"}},
		},
	}
	got := LegacyModelSummaryResults(in)
	c.Assert(got.Results, qt.HasLen, 3)

	c.Assert(got.Results[0].Result, qt.IsNotNil)
	c.Check(got.Results[0].Result.OwnerTag, qt.Equals, "user-alice@external")

	c.Check(got.Results[1].Result, qt.IsNil)
	c.Check(got.Results[1].Error, qt.DeepEquals, &jujuparams.Error{Message: "boom"})

	c.Check(got.Results[2].Result, qt.IsNil)
	c.Check(got.Results[2].Error, qt.IsNotNil)
}

func TestOfferFilters(t *testing.T) {
	c := qt.New(t)

	in := jujuparams.OfferFiltersLegacy{
		Filters: []jujuparams.OfferFilterLegacy{
			{
				OwnerName:       "alice@external",
				ModelName:       "mymodel",
				OfferName:       "myoffer",
				ApplicationName: "myapp",
			},
			{ModelName: "othermodel"}, // empty owner name stays empty
		},
	}
	got := OfferFilters(in)
	c.Assert(got.Filters, qt.HasLen, 2)
	c.Check(got.Filters[0], qt.DeepEquals, jujuparams.OfferFilter{
		ModelQualifier:  "alice@external",
		ModelName:       "mymodel",
		OfferName:       "myoffer",
		ApplicationName: "myapp",
	})
	c.Check(got.Filters[1].ModelQualifier, qt.Equals, "")
	c.Check(got.Filters[1].ModelName, qt.Equals, "othermodel")
}

func TestTransformOfferURLs(t *testing.T) {
	c := qt.New(t)

	got := TransformOfferURLs([]string{
		"alice@external/mymodel.myoffer",
		"this is not a valid offer url",
	})
	c.Assert(got, qt.HasLen, 2)

	// A valid URL is rewritten into qualifier form (here, already canonical).
	url, err := crossmodel.ParseOfferURL(got[0])
	c.Assert(err, qt.IsNil)
	c.Check(url.ModelQualifier, qt.Equals, "alice@external")
	c.Check(url.ModelName, qt.Equals, "mymodel")
	c.Check(url.Name, qt.Equals, "myoffer")

	// An unparseable URL is passed through unchanged.
	c.Check(got[1], qt.Equals, "this is not a valid offer url")
}
