// Copyright 2026 Canonical.

package testing

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/juju/juju/api/client/applicationoffers"
	jujuparams "github.com/juju/juju/rpc/params"
)

// TestApplicationOffersV5ListAndFind checks the ApplicationOffers facade
// version 5 (Juju 3.6) ListApplicationOffers and FindApplicationOffers handlers
// accept a filter that identifies the model by owner name (the 3.6 wire form),
// which JIMM converts to a qualifier before delegating to the v6 handler.
//
// These are read operations, so JIMM brokers and translates them against a
// backing controller of any version and they do not require a Juju 3.x
// controller. The offer itself is created with the v6 client.
func TestApplicationOffersV5ListAndFind(t *testing.T) {
	c := qt.New(t)
	s, model := SetupAppOfferTest(c)

	conn := s.Open(c, nil, "bob@canonical.com", nil)
	defer conn.Close()

	client := applicationoffers.NewClient(conn)
	results, err := client.Offer(t.Context(),
		model.UUID.String, "test-app", []string{"source"}, "bob@canonical.com", "test-offer", "")
	c.Assert(err, qt.IsNil)
	c.Assert(results, qt.HasLen, 1)
	c.Assert(results[0].Error, qt.Equals, (*jujuparams.Error)(nil))

	// The 3.6 filter identifies the model by owner name rather than qualifier.
	filters := jujuparams.OfferFiltersLegacy{
		Filters: []jujuparams.OfferFilterLegacy{{
			OwnerName: model.Owner.Name,
			ModelName: model.Name,
			OfferName: "test-offer",
		}},
	}

	var listResult jujuparams.QueryApplicationOffersResultsV5
	err = conn.APICall(t.Context(), "ApplicationOffers", 5, "", "ListApplicationOffers", filters, &listResult)
	c.Assert(err, qt.IsNil)
	c.Assert(listResult.Results, qt.HasLen, 1)
	c.Check(listResult.Results[0].OfferName, qt.Equals, "test-offer")

	var findResult jujuparams.QueryApplicationOffersResultsV5
	err = conn.APICall(t.Context(), "ApplicationOffers", 5, "", "FindApplicationOffers", filters, &findResult)
	c.Assert(err, qt.IsNil)
	c.Assert(findResult.Results, qt.HasLen, 1)
	c.Check(findResult.Results[0].OfferName, qt.Equals, "test-offer")
}
