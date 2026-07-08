// Copyright 2026 Canonical.

package jujuapi_test

import (
	"context"
	"fmt"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/canonical/jimm/v3/internal/dbmodel"
	"github.com/canonical/jimm/v3/internal/jimmhttp"
	"github.com/canonical/jimm/v3/internal/jujuapi"
)

func TestPathHandling(t *testing.T) {
	c := qt.New(t)

	testUUID := "059744f6-26d2-4f00-92be-5df97fccbb97"
	tests := []struct {
		path      string
		uuid      string
		finalPath string
		fail      bool
	}{
		{path: fmt.Sprintf("/%s/api", testUUID), uuid: testUUID, finalPath: "api", fail: false},
		{path: fmt.Sprintf("/%s/api/", testUUID), uuid: testUUID, finalPath: "api/", fail: false},
		{path: fmt.Sprintf("/%s/api/foo", testUUID), uuid: testUUID, finalPath: "api/foo", fail: false},
		{path: fmt.Sprintf("/%s/commands", testUUID), uuid: testUUID, finalPath: "commands", fail: false},
		{path: fmt.Sprintf("%s/commands", testUUID), fail: true},
		{path: fmt.Sprintf("/model/%s/commands", testUUID), fail: true},
		{path: "/model/123/commands", fail: true},
		{path: fmt.Sprintf("/controller/%s/commands", testUUID), fail: true},
		{path: fmt.Sprintf("/controller/%s/", testUUID), fail: true},
		{path: "/controller", fail: true},
	}
	for i, test := range tests {
		c.Logf("Running test %d for path %s", i, test.path)
		uuid, finalPath, err := jujuapi.ModelInfoFromPath(test.path)
		if !test.fail {
			c.Assert(err, qt.IsNil)
			c.Assert(uuid, qt.Equals, test.uuid)
			c.Assert(finalPath, qt.Equals, test.finalPath)
		} else {
			c.Assert(err, qt.IsNotNil)
		}
	}
}

// TestCheckClientModelCompatibility verifies the model-proxy compatibility
// rule from the JIMM/Juju interoperability spec: a client may connect to
// models hosted on controllers of major version <= its reported major
// version; a client reporting no (or an unparseable) version is treated as a
// Juju 3.6 client, and a controller whose agent version is unknown cannot be
// established as compatible (both fail closed).
func TestCheckClientModelCompatibility(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		about             string
		clientVersion     string
		controllerVersion string
		expectError       string
	}{{
		about:             "unversioned client reaches a 3.6 model",
		clientVersion:     "",
		controllerVersion: "3.6.9",
	}, {
		about:             "unversioned client is refused a 4.x model",
		clientVersion:     "",
		controllerVersion: "4.0.2",
		expectError:       `your Juju client is not compatible with model "prod" \(4\.0\.2\); please upgrade your Juju client to interact with this model`,
	}, {
		about:             "3.6 client is refused a 4.x model",
		clientVersion:     "3.6.8",
		controllerVersion: "4.0.2",
		expectError:       `your Juju client is not compatible with model "prod" \(4\.0\.2\); please upgrade your Juju client to interact with this model`,
	}, {
		about:             "3.6 client reaches a 3.6 model",
		clientVersion:     "3.6.8",
		controllerVersion: "3.6.9",
	}, {
		about:             "4.x client reaches a 4.x model",
		clientVersion:     "4.0.2",
		controllerVersion: "4.0.5",
	}, {
		about:             "4.x client reaches a 3.6 model",
		clientVersion:     "4.0.2",
		controllerVersion: "3.6.9",
	}, {
		about:             "client with unparseable version is treated as 3.6",
		clientVersion:     "not-a-version",
		controllerVersion: "4.0.2",
		expectError:       `your Juju client is not compatible with model "prod" \(4\.0\.2\); please upgrade your Juju client to interact with this model`,
	}, {
		about:             "unknown controller version is rejected",
		clientVersion:     "4.0.2",
		controllerVersion: "",
		expectError:       `cannot establish that your Juju client is compatible with model "prod": the hosting controller's version is unknown`,
	}}

	for _, test := range tests {
		c.Run(test.about, func(c *qt.C) {
			ctx := context.Background()
			if test.clientVersion != "" {
				ctx = jimmhttp.ContextWithClientVersion(ctx, test.clientVersion)
			}
			m := dbmodel.Model{
				Name: "prod",
				Controller: dbmodel.Controller{
					Name:         "test-controller",
					AgentVersion: test.controllerVersion,
				},
			}
			err := jujuapi.CheckClientModelCompatibility(ctx, &m)
			if test.expectError == "" {
				c.Check(err, qt.IsNil)
			} else {
				c.Check(err, qt.ErrorMatches, test.expectError)
			}
		})
	}
}
