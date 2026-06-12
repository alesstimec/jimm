// Copyright 2026 Canonical.

package jujuapi

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestControllerRootClientVersionTracking(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		about           string
		headerVersion   string
		loginVersion    string
		expectedVersion string
	}{{
		about:           "seeded from the upgrade header",
		headerVersion:   "3.6.4",
		expectedVersion: "3.6.4",
	}, {
		about:           "login request version overwrites the header version",
		headerVersion:   "3.6.4",
		loginVersion:    "4.0.2",
		expectedVersion: "4.0.2",
	}, {
		about:           "empty login request version keeps the header version",
		headerVersion:   "3.6.4",
		loginVersion:    "",
		expectedVersion: "3.6.4",
	}, {
		about:           "no version reported",
		expectedVersion: "",
	}, {
		about:           "login request version with no header version",
		loginVersion:    "4.0.2",
		expectedVersion: "4.0.2",
	}}

	for _, test := range tests {
		c.Run(test.about, func(c *qt.C) {
			r := newControllerRoot(nil, Params{}, "", test.headerVersion)
			defer r.cleanup()

			r.setClientVersion(test.loginVersion)

			r.mu.Lock()
			defer r.mu.Unlock()
			c.Check(r.clientVersion, qt.Equals, test.expectedVersion)
		})
	}
}
