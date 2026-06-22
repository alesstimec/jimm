// Copyright 2026 Canonical.

package jujuapi_test

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/juju/juju/core/crossmodel"
	jujuparams "github.com/juju/juju/rpc/params"

	"github.com/canonical/jimm/v3/internal/jujuapi"
	"github.com/canonical/jimm/v3/internal/openfga"
	"github.com/canonical/jimm/v3/internal/testutils/jimmtest/mocks"
)

// TestApplicationOffersAdvertisesLegacyAndCurrent asserts the ApplicationOffers
// facade advertises both the 3.6 (v5) and 4.x (v6) versions.
func TestApplicationOffersAdvertisesLegacyAndCurrent(t *testing.T) {
	c := qt.New(t)
	c.Assert(jujuapi.SupportedFacades()["ApplicationOffers"], qt.DeepEquals, []int{5, 6})
}

// TestListApplicationOffersLegacy checks the v5 ListApplicationOffers handler
// converts the model owner name in the filter to a qualifier and delegates to
// the v6 handler.
func TestListApplicationOffersLegacy(t *testing.T) {
	c := qt.New(t)

	var gotFilters []crossmodel.ApplicationOfferFilter
	jujuManager := mocks.JujuManager{
		ListApplicationOffers_: func(ctx context.Context, user *openfga.User, filters ...crossmodel.ApplicationOfferFilter) ([]*crossmodel.ApplicationOfferDetails, error) {
			gotFilters = filters
			return nil, nil
		},
	}
	cr := newTestControllerRoot(jujuJIMM(&jujuManager), "alice@external", true)

	_, err := cr.ListApplicationOffersLegacy(context.Background(), jujuparams.OfferFiltersLegacy{
		Filters: []jujuparams.OfferFilterLegacy{{
			OwnerName: "alice@external",
			ModelName: "mymodel",
			OfferName: "myoffer",
		}},
	})
	c.Assert(err, qt.IsNil)
	c.Assert(gotFilters, qt.HasLen, 1)
	c.Check(string(gotFilters[0].ModelQualifier), qt.Equals, "alice@external")
	c.Check(gotFilters[0].ModelName, qt.Equals, "mymodel")
	c.Check(gotFilters[0].OfferName, qt.Equals, "myoffer")
}

// TestFindApplicationOffersLegacy checks the v5 FindApplicationOffers handler
// performs the same owner-name -> qualifier filter conversion.
func TestFindApplicationOffersLegacy(t *testing.T) {
	c := qt.New(t)

	var gotFilters []crossmodel.ApplicationOfferFilter
	jujuManager := mocks.JujuManager{
		FindApplicationOffers_: func(ctx context.Context, user *openfga.User, filters ...crossmodel.ApplicationOfferFilter) ([]*crossmodel.ApplicationOfferDetails, error) {
			gotFilters = filters
			return nil, nil
		},
	}
	cr := newTestControllerRoot(jujuJIMM(&jujuManager), "alice@external", true)

	_, err := cr.FindApplicationOffersLegacy(context.Background(), jujuparams.OfferFiltersLegacy{
		Filters: []jujuparams.OfferFilterLegacy{{
			OwnerName: "alice@external",
			ModelName: "mymodel",
		}},
	})
	c.Assert(err, qt.IsNil)
	c.Assert(gotFilters, qt.HasLen, 1)
	c.Check(string(gotFilters[0].ModelQualifier), qt.Equals, "alice@external")
	c.Check(gotFilters[0].ModelName, qt.Equals, "mymodel")
}
