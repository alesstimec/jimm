// Copyright 2026 Canonical.

package rpcproxy

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/canonical/jimm/v3/internal/dbmodel"
	"github.com/canonical/jimm/v3/internal/openfga"
)

// versionTestLoginService implements the login methods used by
// handleAdminFacade, returning a fixed user.
type versionTestLoginService struct {
	LoginService
}

func (s versionTestLoginService) login() (*openfga.User, error) {
	identity, err := dbmodel.NewIdentity("alice@wonderland.io")
	if err != nil {
		return nil, err
	}
	return openfga.NewUser(identity, nil), nil
}

func (s versionTestLoginService) LoginWithSessionToken(ctx context.Context, sessionToken string) (*openfga.User, error) {
	return s.login()
}

func (s versionTestLoginService) LoginClientCredentials(ctx context.Context, clientID string, clientSecret string) (*openfga.User, error) {
	return s.login()
}

// versionTestTokenGenerator implements the token generation used by
// handleAdminFacade.
type versionTestTokenGenerator struct {
	TokenGenerator
}

func (g versionTestTokenGenerator) MakeLoginToken(ctx context.Context, user *openfga.User) ([]byte, error) {
	return []byte("test token"), nil
}

func TestHandleAdminFacadeTracksClientVersion(t *testing.T) {
	c := qt.New(t)

	tests := []struct {
		about           string
		headerVersion   string
		request         string
		params          string
		expectedVersion string
	}{{
		about:           "login with session token reporting a version",
		request:         "LoginWithSessionToken",
		params:          `{"session-token": "test token", "client-version": "4.0.2"}`,
		expectedVersion: "4.0.2",
	}, {
		about:           "login with session token overwrites the header version",
		headerVersion:   "3.6.4",
		request:         "LoginWithSessionToken",
		params:          `{"session-token": "test token", "client-version": "4.0.2"}`,
		expectedVersion: "4.0.2",
	}, {
		about:           "login with session token reporting no version keeps the header version",
		headerVersion:   "3.6.4",
		request:         "LoginWithSessionToken",
		params:          `{"session-token": "test token"}`,
		expectedVersion: "3.6.4",
	}, {
		about:           "login with client credentials reporting a version",
		request:         "LoginWithClientCredentials",
		params:          `{"client-id": "test-client", "client-secret": "test-secret", "client-version": "3.6.4"}`,
		expectedVersion: "3.6.4",
	}, {
		about:           "login with client credentials reporting no version",
		request:         "LoginWithClientCredentials",
		params:          `{"client-id": "test-client", "client-secret": "test-secret"}`,
		expectedVersion: "",
	}}

	for _, test := range tests {
		c.Run(test.about, func(c *qt.C) {
			p := &clientProxy{
				modelProxy: modelProxy{
					loginService:  versionTestLoginService{},
					tokenGen:      versionTestTokenGenerator{},
					clientVersion: test.headerVersion,
				},
			}
			msg := &message{
				RequestID: 1,
				Type:      "Admin",
				Version:   4,
				Request:   test.request,
				Params:    []byte(test.params),
			}
			clientResponse, controllerMessage, err := p.handleAdminFacade(context.Background(), msg)
			c.Assert(err, qt.IsNil)
			c.Assert(clientResponse, qt.IsNil)
			c.Assert(controllerMessage, qt.IsNotNil)
			c.Check(p.clientVersion, qt.Equals, test.expectedVersion)
		})
	}
}
