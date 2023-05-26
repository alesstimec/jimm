// Copyright 2023 Canonical Ltd.
package jujuclient_test

import (
	"context"

	jujuparams "github.com/juju/juju/rpc/params"
	"github.com/juju/names/v4"
	gc "gopkg.in/check.v1"

	"github.com/CanonicalLtd/jimm/internal/dbmodel"
	"github.com/CanonicalLtd/jimm/internal/jimmtest"
)

type storageSuite struct {
	jujuclientSuite
}

var _ = gc.Suite(&storageSuite{})

func (s *storageSuite) TestListFilesystems(c *gc.C) {
	ctx := context.Background()

	cct := names.NewCloudCredentialTag(jimmtest.TestCloudName + "/bob@external/pw1").String()
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
		Name:          s.ControllerConfig.ControllerName(),
		CACertificate: info.CACert,
		AdminUser:     info.Tag.Id(),
		AdminPassword: info.Password,
		PublicAddress: info.Addrs[0],
	}

	models, err := s.API.UpdateCredential(ctx, cred)
	c.Assert(err, gc.Equals, nil)
	c.Assert(models, gc.HasLen, 0)

	var modelInfo jujuparams.ModelInfo
	err = s.API.CreateModel(ctx, &jujuparams.ModelCreateArgs{
		Name:               "model-1",
		OwnerTag:           names.NewUserTag("bob@external").String(),
		CloudCredentialTag: cct,
	}, &modelInfo)
	c.Assert(err, gc.Equals, nil)
	uuid := modelInfo.UUID

	api, err := s.Dialer.Dial(context.Background(), &ctl, names.NewModelTag(uuid))
	c.Assert(err, gc.IsNil)
	_, err = api.ListFilesystems(ctx, nil)
	c.Assert(err, gc.IsNil)
	// TODO(ale8k): figure out how to add storage to mock models and check res after it
	// for now this just tests the facade is called correctly I guess.
}

func (s *storageSuite) TestListVolumes(c *gc.C) {
	ctx := context.Background()

	cct := names.NewCloudCredentialTag(jimmtest.TestCloudName + "/bob@external/pw1").String()
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
		Name:          s.ControllerConfig.ControllerName(),
		CACertificate: info.CACert,
		AdminUser:     info.Tag.Id(),
		AdminPassword: info.Password,
		PublicAddress: info.Addrs[0],
	}

	models, err := s.API.UpdateCredential(ctx, cred)
	c.Assert(err, gc.Equals, nil)
	c.Assert(models, gc.HasLen, 0)

	var modelInfo jujuparams.ModelInfo
	err = s.API.CreateModel(ctx, &jujuparams.ModelCreateArgs{
		Name:               "model-1",
		OwnerTag:           names.NewUserTag("bob@external").String(),
		CloudCredentialTag: cct,
	}, &modelInfo)
	c.Assert(err, gc.Equals, nil)
	uuid := modelInfo.UUID

	api, err := s.Dialer.Dial(context.Background(), &ctl, names.NewModelTag(uuid))
	c.Assert(err, gc.IsNil)
	_, err = api.ListVolumes(ctx, nil)
	c.Assert(err, gc.IsNil)
	// TODO(ale8k): figure out how to add storage to mock models and check res after it
	// for now this just tests the facade is called correctly I guess.
}

func (s *storageSuite) TestListStorageDetails(c *gc.C) {
	ctx := context.Background()

	cct := names.NewCloudCredentialTag(jimmtest.TestCloudName + "/bob@external/pw1").String()
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
		Name:          s.ControllerConfig.ControllerName(),
		CACertificate: info.CACert,
		AdminUser:     info.Tag.Id(),
		AdminPassword: info.Password,
		PublicAddress: info.Addrs[0],
	}

	models, err := s.API.UpdateCredential(ctx, cred)
	c.Assert(err, gc.Equals, nil)
	c.Assert(models, gc.HasLen, 0)

	var modelInfo jujuparams.ModelInfo
	err = s.API.CreateModel(ctx, &jujuparams.ModelCreateArgs{
		Name:               "model-1",
		OwnerTag:           names.NewUserTag("bob@external").String(),
		CloudCredentialTag: cct,
	}, &modelInfo)
	c.Assert(err, gc.Equals, nil)
	uuid := modelInfo.UUID

	api, err := s.Dialer.Dial(context.Background(), &ctl, names.NewModelTag(uuid))
	c.Assert(err, gc.IsNil)
	_, err = api.ListStorageDetails(ctx)
	c.Assert(err, gc.IsNil)
	// TODO(ale8k): figure out how to add storage to mock models and check res after it
	// for now this just tests the facade is called correctly I guess.
}