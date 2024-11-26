// Copyright 2024 Canonical.

package jimmhttp

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/juju/names/v4"
	"gopkg.in/errgo.v1"

	"github.com/canonical/jimm/v3/internal/dbmodel"
	"github.com/canonical/jimm/v3/internal/jimm/credentials"
	"github.com/canonical/jimm/v3/internal/middleware"
	"github.com/canonical/jimm/v3/internal/openfga"
	ofganames "github.com/canonical/jimm/v3/internal/openfga/names"
	"github.com/canonical/jimm/v3/internal/rpc"
)

// JIMM defines an interface used by the HTTPProxyHandler to get authentication
// information.
type JIMM interface {
	AuthenticateBrowserSession(context.Context, http.ResponseWriter, *http.Request) (context.Context, error)
	GetCredentialStore() credentials.CredentialStore
	GetModel(ctx context.Context, uuid string) (dbmodel.Model, error)
	LoginWithSessionToken(ctx context.Context, sessionToken string) (*openfga.User, error)
	UserLogin(ctx context.Context, identityName string) (*openfga.User, error)
}

// HTTPProxyHandler is an handler that provides proxying capabilities.
// It uses the uuid in the path to proxy requests to model's controller.
type HTTPProxyHandler struct {
	Router *chi.Mux
	jimm   JIMM
}

const (
	// all endpoints managed by this handler
	ProxyEndpoints = "/*"
)

// NewHTTPProxyHandler creates a proxy http handler.
func NewHTTPProxyHandler(jimm JIMM) *HTTPProxyHandler {
	return &HTTPProxyHandler{Router: chi.NewRouter(), jimm: jimm}
}

// Routes returns the grouped routers routes with group specific middlewares.
func (hph *HTTPProxyHandler) Routes() chi.Router {
	hph.SetupMiddleware()
	hph.Router.HandleFunc(ProxyEndpoints, hph.ProxyHTTP)
	return hph.Router
}

// SetupMiddleware applies authn and authz middlewares.
func (hph *HTTPProxyHandler) SetupMiddleware() {
	hph.Router.Use(func(h http.Handler) http.Handler {
		return middleware.AuthenticateWithSessionTokenViaBasicAuth(h, hph.jimm)
	})
	hph.Router.Use(func(h http.Handler) http.Handler {
		return middleware.AuthorizeUserForModelAccess(h, ofganames.WriterRelation)
	})
}

// ProxyHTTP extracts the model uuid from the path to proxy the request to the right controller.
func (hph *HTTPProxyHandler) ProxyHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	modelUUID := chi.URLParam(req, "uuid")
	if modelUUID == "" {
		writeError(ctx, w, http.StatusUnprocessableEntity, errgo.New("cannot parse path"), "cannot parse path")
		return
	}
	model, err := hph.jimm.GetModel(ctx, modelUUID)
	if err != nil {
		writeError(ctx, w, http.StatusNotFound, err, "cannot get model")
		return
	}
	u, p, err := hph.jimm.GetCredentialStore().GetControllerCredentials(ctx, model.Controller.Name)
	if err != nil {
		writeError(ctx, w, http.StatusNotFound, err, "cannot retrieve credentials")
		return
	}
	req.SetBasicAuth(names.NewUserTag(u).String(), p)

	err = rpc.ProxyHTTP(ctx, &model.Controller, w, req)
	if err != nil {
		writeError(ctx, w, http.StatusGatewayTimeout, err, "Gateway timeout")
	}
}
