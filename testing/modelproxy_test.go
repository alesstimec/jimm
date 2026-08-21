// Copyright 2026 Canonical.

package testing

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"testing"

	petname "github.com/dustinkirkland/golang-petname"
	qt "github.com/frankban/quicktest"
	"github.com/gorilla/websocket"
	"github.com/juju/juju/api"
	jujuparams "github.com/juju/juju/rpc/params"
	"github.com/juju/names/v6"
	"github.com/juju/version/v2"

	"github.com/canonical/jimm/v3/internal/dbmodel"
	"github.com/canonical/jimm/v3/internal/testutils/jimmtest"
)

// TestModelProxyClientCompatibilityJuju3Controller verifies the model
// proxy's client/model compatibility gate for models hosted on Juju 3.x
// controllers: every client — unversioned (treated as Juju 3.6), 3.6, and
// 4.x — may interact with the model. Skipped when the environment provides
// no 3.x backing controller.
func TestModelProxyClientCompatibilityJuju3Controller(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	fleet := backingControllersMatching(c, s, func(major int) bool { return major <= 3 })
	if len(fleet) == 0 {
		c.Skip("no Juju 3.x backing controller in the environment")
	}
	for _, ctl := range fleet {
		c.Run(fmt.Sprintf("model hosted on %s (%s)", ctl.name, ctl.agent), func(c *qt.C) {
			model := createModelOn(c, s, ctl.name)
			mt := model.ResourceTag()

			for _, test := range []struct {
				about         string
				clientVersion string
			}{{
				about:         "unversioned client is treated as Juju 3.6 and connects",
				clientVersion: "",
			}, {
				about:         "client reporting 3.6 connects",
				clientVersion: "3.6.8",
			}, {
				about:         "client reporting 4.x connects",
				clientVersion: "4.0.2",
			}} {
				c.Run(test.about, func(c *qt.C) {
					assertModelInteraction(c, s, mt, test.clientVersion)
				})
			}
			assertAgentLoginNotGated(c, s, mt)
			assertDiscoveryUnfiltered(c, s, model)
		})
	}
}

// TestModelProxyClientCompatibilityJuju4Controller verifies the model
// proxy's client/model compatibility gate for models hosted on Juju 4.x
// controllers: unversioned (treated as Juju 3.6) and 3.6 clients are
// rejected with an upgrade error, while a 4.x client connects. Agent logins
// and discovery are unaffected by the gate. Skipped when the environment
// provides no 4.x backing controller.
func TestModelProxyClientCompatibilityJuju4Controller(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	fleet := backingControllersMatching(c, s, func(major int) bool { return major >= 4 })
	if len(fleet) == 0 {
		c.Skip("no Juju 4.x backing controller in the environment")
	}
	for _, ctl := range fleet {
		c.Run(fmt.Sprintf("model hosted on %s (%s)", ctl.name, ctl.agent), func(c *qt.C) {
			model := createModelOn(c, s, ctl.name)
			mt := model.ResourceTag()

			incompatibleErr := fmt.Sprintf(
				`.*your Juju client is not compatible with model %s \(%s\); please upgrade your Juju client to interact with this model.*`,
				regexp.QuoteMeta(fmt.Sprintf("%q", model.Name)),
				regexp.QuoteMeta(ctl.agent))

			for _, test := range []struct {
				about         string
				clientVersion string
			}{{
				about:         "unversioned client is treated as Juju 3.6 and rejected",
				clientVersion: "",
			}, {
				about:         "client reporting 3.6 is rejected",
				clientVersion: "3.6.8",
			}} {
				c.Run(test.about, func(c *qt.C) {
					conn, err := openModelProxy(c, s, mt, test.clientVersion)
					c.Assert(err, qt.ErrorMatches, incompatibleErr)
					if conn != nil {
						conn.Close()
					}
				})
			}
			c.Run("client reporting 4.x connects", func(c *qt.C) {
				assertModelInteraction(c, s, mt, "4.0.2")
			})
			assertAgentLoginNotGated(c, s, mt)
			assertDiscoveryUnfiltered(c, s, model)
		})
	}
}

// backingController identifies a registered backing controller and its agent
// version.
type backingController struct {
	name  string
	agent string
}

// backingControllersMatching returns the backing controllers whose agent
// major version satisfies match.
func backingControllersMatching(c *qt.C, s jimmtest.JimmWithControllers, match func(major int) bool) []backingController {
	var fleet []backingController
	err := s.JIMM.Database.ForEachController(c.Context(), func(ctl *dbmodel.Controller) error {
		v, err := version.Parse(ctl.AgentVersion)
		if err != nil {
			return fmt.Errorf("controller %q has an unparseable agent version %q: %w", ctl.Name, ctl.AgentVersion, err)
		}
		if match(v.Major) {
			fleet = append(fleet, backingController{name: ctl.Name, agent: ctl.AgentVersion})
		}
		return nil
	})
	c.Assert(err, qt.IsNil)
	return fleet
}

// createModelOn creates a model for bob pinned to the named controller.
func createModelOn(c *qt.C, s jimmtest.JimmWithControllers, controllerName string) *dbmodel.Model {
	return s.CreateModel(c, jimmtest.AddModelArgs{
		Name:                 petname.Generate(2, "-"),
		Owner:                bobOwnerTag,
		Cloud:                names.NewCloudTag(jimmtest.TestE2ECloudName),
		Region:               jimmtest.TestE2ECloudRegionName,
		Cred:                 s.BobCredential.ResourceTag(),
		TargetControllerName: controllerName,
	})
}

// openModelProxy dials the model's API endpoint through JIMM's model proxy,
// reporting the given client version ("" dials without the
// X-Juju-ClientVersion header, as a real Juju 3.6 CLI does).
func openModelProxy(c *qt.C, s jimmtest.JimmWithControllers, mt names.ModelTag, clientVersion string) (api.Connection, error) {
	d := jimmtest.LoginDetails{Username: bobOwnerTag.Id()}
	if clientVersion == "" {
		d.NoClientVersion = true
	} else {
		d.DialWebsocket = jimmtest.DialWebsocketWithClientVersion(clientVersion)
	}
	return s.OpenNoAssert(c, d, &mt)
}

// assertModelInteraction opens the model's API endpoint reporting the given
// client version and proves traffic flows both ways over the proxied
// connection. Login already crossed the proxied controller leg; the Ping
// proves an established two-way path.
func assertModelInteraction(c *qt.C, s jimmtest.JimmWithControllers, mt names.ModelTag, clientVersion string) {
	conn, err := openModelProxy(c, s, mt, clientVersion)
	c.Assert(err, qt.IsNil)
	defer conn.Close()
	err = conn.APICall(c.Context(), "Pinger", 1, "", "Ping", nil, nil)
	c.Check(err, qt.IsNil)
}

// assertAgentLoginNotGated verifies that agents are exempt from the
// compatibility gate: an agent's legacy login (no client version reported)
// is answered with a redirect to the backing controller, never the
// compatibility error.
func assertAgentLoginNotGated(c *qt.C, s jimmtest.JimmWithControllers, mt names.ModelTag) {
	c.Run("agent login is not gated", func(c *qt.C) {
		resp := legacyAgentLogin(c, s, mt, names.NewMachineTag("0").String())
		c.Check(resp.Error, qt.Equals, "redirection to alternative server required")
		c.Check(resp.ErrorCode, qt.Equals, "redirection required")
	})
}

// assertDiscoveryUnfiltered verifies that discovery is deliberately not
// filtered: a client that cannot connect to the model can still see it at
// the controller level.
func assertDiscoveryUnfiltered(c *qt.C, s jimmtest.JimmWithControllers, model *dbmodel.Model) {
	c.Run("discovery is not filtered for an unversioned client", func(c *qt.C) {
		conn := s.OpenNoClientVersion(c, nil, bobOwnerTag.Id(), nil)
		defer conn.Close()

		var res jujuparams.ModelInfoResultsLegacy
		err := conn.APICall(c.Context(), "ModelManager", 10, "", "ModelInfo",
			jujuparams.Entities{Entities: []jujuparams.Entity{{Tag: model.ResourceTag().String()}}}, &res)
		c.Assert(err, qt.IsNil)
		c.Assert(res.Results, qt.HasLen, 1)
		c.Assert(res.Results[0].Error == nil, qt.IsTrue,
			qt.Commentf("ModelInfo error: %v", res.Results[0].Error))
		c.Check(res.Results[0].Result.UUID, qt.Equals, model.UUID.String)
	})
}

// rpcMessage is a raw Juju RPC frame, for hand-crafting calls the juju api
// client cannot make (an agent's legacy Login).
type rpcMessage struct {
	RequestID uint64          `json:"request-id"`
	Type      string          `json:"type,omitempty"`
	Version   int             `json:"version,omitempty"`
	Request   string          `json:"request,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Error     string          `json:"error,omitempty"`
	ErrorCode string          `json:"error-code,omitempty"`
	ErrorInfo map[string]any  `json:"error-info,omitempty"`
	Response  json.RawMessage `json:"response,omitempty"`
}

// legacyAgentLogin dials the model's API endpoint through JIMM's model
// proxy exactly as a Juju agent does — no X-Juju-ClientVersion header — and
// performs a legacy Admin.Login with the given agent tag, returning the
// response frame.
func legacyAgentLogin(c *qt.C, s jimmtest.JimmWithControllers, mt names.ModelTag, authTag string) rpcMessage {
	u, err := url.Parse(s.HTTP.URL)
	c.Assert(err, qt.IsNil)
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 test server
	}
	conn, resp, err := dialer.Dial(fmt.Sprintf("wss://%s/model/%s/api", u.Host, mt.Id()), nil)
	c.Assert(err, qt.IsNil)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	defer conn.Close()

	params, err := json.Marshal(jujuparams.LoginRequest{AuthTag: authTag})
	c.Assert(err, qt.IsNil)
	err = conn.WriteJSON(rpcMessage{
		RequestID: 1,
		Type:      "Admin",
		Version:   3,
		Request:   "Login",
		Params:    params,
	})
	c.Assert(err, qt.IsNil)

	var reply rpcMessage
	err = conn.ReadJSON(&reply)
	c.Assert(err, qt.IsNil)
	c.Assert(reply.RequestID, qt.Equals, uint64(1))
	return reply
}
