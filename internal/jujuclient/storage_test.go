// Copyright 2025 Canonical.

package jujuclient_test

import (
	"context"
	"time"

	jujuparams "github.com/juju/juju/rpc/params"
	"github.com/juju/names/v5"
	gc "gopkg.in/check.v1"

	"github.com/canonical/jimm/v3/internal/dbmodel"
	"github.com/canonical/jimm/v3/internal/jimm/juju"
	"github.com/canonical/jimm/v3/internal/openfga"
	"github.com/canonical/jimm/v3/internal/testutils/jimmtest"
)

type storageSuite struct {
	jujuclientSuite
}

var _ = gc.Suite(&storageSuite{})

func (s *storageSuite) TestListFilesystems(c *gc.C) {
	ctx := context.Background()

	cct := names.NewCloudCredentialTag(jimmtest.TestCloudName + "/bob@canonical.com/pw1")
	ut := names.NewUserTag("bob@canonical.com")

	s.UpdateCloudCredential(c,
		cct,
		jujuparams.CloudCredential{
			AuthType: "userpass",
			Attributes: map[string]string{
				"username": "alibaba",
				"password": "open sesame",
			},
		},
	)

	info := s.APIInfo(c)
	ctl := dbmodel.Controller{
		UUID:          s.ControllerConfig.ControllerUUID(),
		Name:          s.ControllerConfig.ControllerName(),
		CACertificate: info.CACert,
		PublicAddress: info.Addrs[0],
	}

	mt := s.AddModel(c, ut, "model-1", names.NewCloudTag(jimmtest.TestCloudName), jimmtest.TestCloudRegionName, cct)

	err := s.OFGAClient.AddControllerModel(ctx, ctl.ResourceTag(), mt)
	c.Assert(err, gc.IsNil)

	api := mustDialWithRetries(c, s.Dialer, s.AdminUser, &ctl, mt)
	_, err = api.ListFilesystems(ctx, nil)
	c.Assert(err, gc.IsNil)
	// TODO(ale8k): figure out how to add storage to mock models and check res after it
	// for now this just tests the facade is called correctly I guess.
}

func (s *storageSuite) TestListVolumes(c *gc.C) {
	ctx := context.Background()

	cct := names.NewCloudCredentialTag(jimmtest.TestCloudName + "/bob@canonical.com/pw1").String()
	cred := jujuparams.TaggedCredential{
		Tag: cct,
		Credential: jujuparams.CloudCredential{
			AuthType: "userpass",
			Attributes: map[string]string{
				"username": "alibaba",
				"password": "open sesame",
			},
		},
	}

	info := s.APIInfo(c)
	ctl := dbmodel.Controller{
		UUID:          s.ControllerConfig.ControllerUUID(),
		Name:          s.ControllerConfig.ControllerName(),
		CACertificate: info.CACert,
		PublicAddress: info.Addrs[0],
	}

	models, err := s.API.UpdateCredential(ctx, cred)
	c.Assert(err, gc.Equals, nil)
	c.Assert(models, gc.HasLen, 0)

	var modelInfo jujuparams.ModelInfo
	err = s.API.CreateModel(ctx, &jujuparams.ModelCreateArgs{
		Name:               "model-1",
		OwnerTag:           names.NewUserTag("bob@canonical.com").String(),
		CloudCredentialTag: cct,
	}, &modelInfo)
	c.Assert(err, gc.Equals, nil)
	uuid := modelInfo.UUID

	api := mustDialWithRetries(c, s.Dialer, s.AdminUser, &ctl, names.NewModelTag(uuid))
	_, err = api.ListVolumes(ctx, nil)
	c.Assert(err, gc.IsNil)
	// TODO(ale8k): figure out how to add storage to mock models and check res after it
	// for now this just tests the facade is called correctly I guess.
}

func (s *storageSuite) TestListStorageDetails(c *gc.C) {
	ctx := context.Background()

	cct := names.NewCloudCredentialTag(jimmtest.TestCloudName + "/bob@canonical.com/pw1")
	cred := jujuparams.TaggedCredential{
		Tag: cct.String(),
		Credential: jujuparams.CloudCredential{
			AuthType: "userpass",
			Attributes: map[string]string{
				"username": "alibaba",
				"password": "open sesame",
			},
		},
	}

	s.UpdateCloudCredential(c, cct, cred.Credential)
	mt := s.AddModel(c, names.NewUserTag("bob@canonical.com"), "model-1", names.NewCloudTag(jimmtest.TestCloudName), "", cct)

	info := s.APIInfo(c)
	ctl := dbmodel.Controller{
		UUID:          s.ControllerConfig.ControllerUUID(),
		Name:          s.ControllerConfig.ControllerName(),
		CACertificate: info.CACert,
		PublicAddress: info.Addrs[0],
	}

	api := mustDialWithRetries(c, s.Dialer, s.AdminUser, &ctl, mt)

	_, err := api.ListStorageDetails(ctx)
	c.Assert(err, gc.IsNil)
	// TODO(ale8k): figure out how to add storage to mock models and check res after it
	// for now this just tests the facade is called correctly I guess.
}

func mustDialWithRetries(c *gc.C, dialer juju.Dialer, user *openfga.User, ctl *dbmodel.Controller, mt names.ModelTag) juju.API {
	var api juju.API
	var err error
	for i := 0; i < 10; i++ {
		api, err = dialer.Dial(context.Background(), user, ctl, mt, nil)
		if err != nil {
			c.Logf("failed to dial the controller")
			time.Sleep(500 * time.Millisecond)
		} else {
			break
		}
	}
	c.Assert(err, gc.IsNil)
	return api
}
