// Copyright 2026 Canonical.

package jujuapi

import (
	"context"
	"reflect"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/juju/juju/rpc/rpcreflect"

	"github.com/canonical/jimm/v3/internal/jujuapi/rpc"
)

// These tests lock in the multi-version facade mechanics that the 3.6-client
// facade work relies on: registering a facade at more than one version must
// (a) advertise every version in the login facade list and (b) dispatch each
// version to its own handler. They also codify the invariant that a facade
// must not advertise a version for which it registers no methods — otherwise a
// client negotiating that version gets a CallNotImplemented error deep inside
// an operation rather than at login.

// TestAdvertisedFacadeVersionsAreRegistered asserts, over the real set of
// facades JIMM serves, that every version advertised by setupFacades has at
// least one method registered. This is the "advertise => register" guard: when
// a facade is bumped to serve an additional (e.g. 3.6) version, forgetting to
// register that version's methods fails here rather than in production.
func TestAdvertisedFacadeVersionsAreRegistered(t *testing.T) {
	c := qt.New(t)

	// newControllerRoot pre-registers Admin/Pinger; setupFacades registers the
	// rest as a side effect of building the advertised list.
	root := newControllerRoot(nil, Params{}, "")
	facades := setupFacades(root)
	c.Assert(len(facades) > 0, qt.IsTrue)

	for _, fv := range facades {
		c.Assert(len(fv.Versions) > 0, qt.IsTrue,
			qt.Commentf("facade %q advertises no versions", fv.Name))
		for _, v := range fv.Versions {
			c.Check(root.HasMethods(fv.Name, v), qt.IsTrue,
				qt.Commentf("facade %q advertises version %d but registers no methods for it", fv.Name, v))
		}
	}
}

type negotiationEchoResult struct {
	Version int `json:"version"`
}

// TestMultiVersionFacadeAdvertisedAndDispatched registers a synthetic facade at
// two versions and asserts both are advertised by setupFacades and each
// dispatches to its own handler, while an unregistered version reports
// CallNotImplemented. This exercises the generic mechanic end to end without
// pinning any real facade's version numbers (Task 8's golden file owns those).
func TestMultiVersionFacadeAdvertisedAndDispatched(t *testing.T) {
	c := qt.New(t)

	const facade = "TestNegotiationFacade"
	facadeInit[facade] = func(r *controllerRoot) []int {
		r.AddMethod(facade, 1, "Echo", rpc.Method(func(context.Context) (negotiationEchoResult, error) {
			return negotiationEchoResult{Version: 1}, nil
		}))
		r.AddMethod(facade, 2, "Echo", rpc.Method(func(context.Context) (negotiationEchoResult, error) {
			return negotiationEchoResult{Version: 2}, nil
		}))
		return []int{1, 2}
	}
	defer delete(facadeInit, facade)

	root := newControllerRoot(nil, Params{}, "")
	facades := setupFacades(root)

	// Both versions are advertised in the login facade list.
	var advertised []int
	for _, fv := range facades {
		if fv.Name == facade {
			advertised = fv.Versions
		}
	}
	c.Assert(advertised, qt.DeepEquals, []int{1, 2})

	// Each advertised version dispatches to its own handler.
	for _, v := range []int{1, 2} {
		caller, err := root.FindMethod(facade, v, "Echo")
		c.Assert(err, qt.IsNil, qt.Commentf("version %d", v))
		res, err := caller.Call(context.Background(), "", reflect.Value{})
		c.Assert(err, qt.IsNil, qt.Commentf("version %d", v))
		c.Check(res.Interface(), qt.Equals, negotiationEchoResult{Version: v})
	}

	// A version that is advertised by no handler is not dispatchable.
	_, err := root.FindMethod(facade, 3, "Echo")
	c.Assert(err, qt.IsNotNil)
	_, isNotImplemented := err.(*rpcreflect.CallNotImplementedError)
	c.Check(isNotImplemented, qt.IsTrue, qt.Commentf("got %T: %v", err, err))
}
