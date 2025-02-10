// Copyright 2025 Canonical.

package jujuclient_test

import (
	"context"
	"time"

	"github.com/google/go-cmp/cmp/cmpopts"
	jujuparams "github.com/juju/juju/rpc/params"
	jujuversion "github.com/juju/juju/version"
	"github.com/juju/names/v5"
	gc "gopkg.in/check.v1"

	"github.com/canonical/jimm/v3/internal/dbmodel"
	"github.com/canonical/jimm/v3/internal/testutils/jimmtest"
)

type clientSuite struct {
	jujuclientSuite
}

var _ = gc.Suite(&clientSuite{})

func (s *clientSuite) TestStatus(c *gc.C) {
	ctx := context.Background()

	ut := names.NewUserTag("bob@canonical.com")
	cct := names.NewCloudCredentialTag(jimmtest.TestCloudName + "/" + ut.Id() + "/pw1")

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
		UUID:          info.ControllerUUID,
		Name:          s.ControllerConfig.ControllerName(),
		CACertificate: info.CACert,
		PublicAddress: info.Addrs[0],
	}

	mt := s.AddModel(c, ut, "model-1", names.NewCloudTag(jimmtest.TestCloudName), jimmtest.TestCloudRegionName, cct)

	api := mustDialWithRetries(c, s.Dialer, s.AdminUser, &ctl, mt)

	status, err := api.Status(ctx, []string{})
	c.Assert(err, gc.Equals, nil)
	c.Assert(status, jimmtest.CmpEquals(cmpopts.IgnoreTypes(&time.Time{})), &jujuparams.FullStatus{
		Model: jujuparams.ModelStatusInfo{
			Name:             "model-1",
			Type:             "iaas",
			CloudTag:         names.NewCloudTag(jimmtest.TestCloudName).String(),
			CloudRegion:      jimmtest.TestCloudRegionName,
			Version:          jujuversion.Current.String(),
			AvailableVersion: "",
			ModelStatus: jujuparams.DetailedStatus{
				Status: "available",
				Info:   "",
				Data:   map[string]interface{}{},
			},
			SLA: "unsupported",
		},
		Machines:           map[string]jujuparams.MachineStatus{},
		Applications:       map[string]jujuparams.ApplicationStatus{},
		RemoteApplications: map[string]jujuparams.RemoteApplicationStatus{},
		Offers:             map[string]jujuparams.ApplicationOfferStatus{},
		Relations:          []jujuparams.RelationStatus(nil),
		Branches:           map[string]jujuparams.BranchStatus{},
	})
}
