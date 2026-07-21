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

// TestModelProxyClientCompatibility exercises the model proxy's
// client/model compatibility gate end to end: a real websocket dial to a
// model's /api endpoint through JIMM carrying a chosen X-Juju-ClientVersion
// header, JIMM's header extraction, and the accept/reject decision taken
// before proxying to the real hosting controller. Per the JIMM/Juju
// interoperability spec, a client may interact with models hosted on
// controllers of major version <= its reported major version, a client that
// reports no version is treated as a Juju 3.6 client (fail closed), and
// discovery (model listings, ModelInfo) is deliberately not filtered —
// incompatibility surfaces only on interaction.
//
// A model is pinned to each backing controller and expectations are derived
// from that controller's agent version, so the test is meaningful whether the
// environment provides 3.x controllers, 4.x controllers, or a mix.
func TestModelProxyClientCompatibility(t *testing.T) {
	c := qt.New(t)
	s := jimmtest.SetupJimmWithControllers(c)

	type backingController struct {
		name  string
		agent string
		major int
	}
	var fleet []backingController
	err := s.JIMM.Database.ForEachController(c.Context(), func(ctl *dbmodel.Controller) error {
		v, err := version.Parse(ctl.AgentVersion)
		if err != nil {
			return fmt.Errorf("controller %q has an unparseable agent version %q: %w", ctl.Name, ctl.AgentVersion, err)
		}
		fleet = append(fleet, backingController{name: ctl.Name, agent: ctl.AgentVersion, major: v.Major})
		return nil
	})
	c.Assert(err, qt.IsNil)
	c.Assert(len(fleet) > 0, qt.IsTrue)

	// openModel dials the model's API endpoint through JIMM's model proxy,
	// reporting the given client version ("" dials without the
	// X-Juju-ClientVersion header, as a real Juju 3.6 CLI does).
	openModel := func(c *qt.C, mt names.ModelTag, clientVersion string) (api.Connection, error) {
		d := jimmtest.LoginDetails{Username: bobOwnerTag.Id()}
		if clientVersion == "" {
			d.NoClientVersion = true
		} else {
			d.DialWebsocket = jimmtest.DialWebsocketWithClientVersion(clientVersion)
		}
		return s.OpenNoAssert(c, d, &mt)
	}

	for _, ctl := range fleet {
		c.Run(fmt.Sprintf("model hosted on %s (%s)", ctl.name, ctl.agent), func(c *qt.C) {
			model := s.CreateModel(c, jimmtest.AddModelArgs{
				Name:                 petname.Generate(2, "-"),
				Owner:                bobOwnerTag,
				Cloud:                names.NewCloudTag(jimmtest.TestE2ECloudName),
				Region:               jimmtest.TestE2ECloudRegionName,
				Cred:                 s.BobCredential.ResourceTag(),
				TargetControllerName: ctl.name,
			})
			mt := model.ResourceTag()

			incompatibleErr := fmt.Sprintf(
				`.*your Juju client is not compatible with model %s \(%s\); please upgrade your Juju client to interact with this model.*`,
				regexp.QuoteMeta(fmt.Sprintf("%q", model.Name)),
				regexp.QuoteMeta(ctl.agent))

			tests := []struct {
				about         string
				clientVersion string
				compatible    bool
			}{{
				about:         "unversioned client is treated as Juju 3.6",
				clientVersion: "",
				compatible:    ctl.major <= 3,
			}, {
				about:         "client reporting 3.6",
				clientVersion: "3.6.8",
				compatible:    ctl.major <= 3,
			}, {
				about:         "client reporting 4.x",
				clientVersion: "4.0.2",
				compatible:    true,
			}}
			for _, test := range tests {
				c.Run(test.about, func(c *qt.C) {
					conn, err := openModel(c, mt, test.clientVersion)
					if !test.compatible {
						c.Assert(err, qt.ErrorMatches, incompatibleErr)
						return
					}
					c.Assert(err, qt.IsNil)
					defer conn.Close()
					// Login already crossed the proxied controller leg; a
					// call over the established connection proves traffic
					// flows both ways.
					err = conn.APICall(c.Context(), "Pinger", 1, "", "Ping", nil, nil)
					c.Check(err, qt.IsNil)
				})
			}

			// Agents are exempt from the compatibility gate. The same
			// /api endpoint serves the model's own agents, which report
			// no client version; after a migration they may be older than
			// the new hosting controller and must still reach it (they
			// speak the agent API the controller itself serves). Their
			// legacy login is answered with a redirect to the backing
			// controller, never with the compatibility error.
			c.Run("agent login is not gated", func(c *qt.C) {
				resp := legacyAgentLogin(c, s, mt, names.NewMachineTag("0").String())
				c.Check(resp.Error, qt.Equals, "redirection to alternative server required")
				c.Check(resp.ErrorCode, qt.Equals, "redirection required")
			})

			// Discovery is deliberately not filtered: a client that cannot
			// connect to the model can still see it at the controller level.
			c.Run("discovery is not filtered for an unversioned client", func(c *qt.C) {
				conn := s.OpenNoClientVersion(c, nil, bobOwnerTag.Id(), nil)
				defer conn.Close()

				var res jujuparams.ModelInfoResultsLegacy
				err := conn.APICall(c.Context(), "ModelManager", 10, "", "ModelInfo",
					jujuparams.Entities{Entities: []jujuparams.Entity{{Tag: mt.String()}}}, &res)
				c.Assert(err, qt.IsNil)
				c.Assert(res.Results, qt.HasLen, 1)
				c.Assert(res.Results[0].Error == nil, qt.IsTrue,
					qt.Commentf("ModelInfo error: %v", res.Results[0].Error))
				c.Check(res.Results[0].Result.UUID, qt.Equals, model.UUID.String)
			})
		})
	}
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

// legacyAgentLogin dials the model's /api endpoint through JIMM's model
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
