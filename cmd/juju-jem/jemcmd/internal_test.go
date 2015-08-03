// Copyright 2015 Canonical Ltd.

package jemcmd

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/juju/juju/juju/osenv"
	corejujutesting "github.com/juju/juju/juju/testing"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/utils"
	gc "gopkg.in/check.v1"
	"gopkg.in/errgo.v1"
	"gopkg.in/juju/environschema.v1"

	"github.com/CanonicalLtd/jem/params"
)

type internalSuite struct {
	corejujutesting.JujuConnSuite
}

var _ = gc.Suite(&internalSuite{})

var entityPathValueTests = []struct {
	about            string
	val              string
	expectEntityPath params.EntityPath
	expectError      string
}{{
	about: "success",
	val:   "foo/bar",
	expectEntityPath: params.EntityPath{
		User: "foo",
		Name: "bar",
	},
}, {
	about:       "only one part",
	val:         "a",
	expectError: `invalid JEM name "a" \(needs to be <user>/<name>\)`,
}, {
	about:       "too many parts",
	val:         "a/b/c",
	expectError: `invalid JEM name "a/b/c" \(needs to be <user>/<name>\)`,
}, {
	about:       "empty server id",
	val:         "",
	expectError: `invalid JEM name "" \(needs to be <user>/<name>\)`,
}}

func (s *internalSuite) TestEntityPathValue(c *gc.C) {
	for i, test := range entityPathValueTests {
		c.Logf("test %d: %s", i, test.about)
		var p entityPathValue
		err := p.Set(test.val)
		if test.expectError != "" {
			c.Assert(err, gc.ErrorMatches, test.expectError)
			continue
		}
		c.Assert(err, gc.IsNil)
		c.Assert(p.EntityPath, gc.Equals, test.expectEntityPath)
	}
}

func (s *internalSuite) TestCreateComnandSetConfigDefaults(c *gc.C) {
	// Note: these values are set up by JujuConnSuite
	// and are not the actual user's home and juju home.
	home := utils.Home()
	jujuHome := osenv.JujuHomePath()
	tests := []struct {
		about   string
		envName string
		jesInfo params.JESResponse
		config  map[string]interface{}

		// envVars holds a map from environment variable
		// name to value. Each entry will be set at the start
		// of the test.
		envVars map[string]string

		// files holds a map from file name to contents.
		// Each entry will be created at the start of the test.
		files map[string]string

		expectError  string
		expectConfig map[string]interface{}
	}{{
		about: "one parameter, no defaults",
		jesInfo: params.JESResponse{
			ProviderType: "something",
			Template: environschema.Fields{
				"attr": {
					Type: environschema.Tstring,
				},
			},
		},
		config: map[string]interface{}{
			"attr": "hello",
		},
		expectConfig: map[string]interface{}{
			"attr": "hello",
		},
	}, {
		about: "environment variable defaults",
		envVars: map[string]string{
			"somevar": "avalue",
		},
		jesInfo: params.JESResponse{
			ProviderType: "something",
			Template: environschema.Fields{
				"attr": {
					Type:   environschema.Tstring,
					EnvVar: "somevar",
				},
			},
		},
		expectConfig: map[string]interface{}{
			"attr": "avalue",
		},
	}, {
		about: "default authorized keys",
		files: map[string]string{
			filepath.Join(home, ".ssh", "id_rsa.pub"): fakeSSHKey,
		},
		jesInfo: params.JESResponse{
			ProviderType: "something",
			Template: environschema.Fields{
				"authorized-keys": {
					Type: environschema.Tstring,
				},
			},
		},
		expectConfig: map[string]interface{}{
			"authorized-keys": fakeSSHKey,
		},
	}, {
		about: "authorized keys from relative path",
		files: map[string]string{
			filepath.Join(home, ".ssh", "another.pub"): fakeSSHKey,
		},
		jesInfo: params.JESResponse{
			ProviderType: "something",
			Template: environschema.Fields{
				"authorized-keys": {
					Type: environschema.Tstring,
				},
			},
		},
		config: map[string]interface{}{
			"authorized-keys-path": "another.pub",
		},
		expectConfig: map[string]interface{}{
			"authorized-keys": fakeSSHKey,
		},
	}, {
		about: "authorized keys from absolute path",
		files: map[string]string{
			filepath.Join(home, "key.pub"): fakeSSHKey,
		},
		jesInfo: params.JESResponse{
			ProviderType: "something",
			Template: environschema.Fields{
				"authorized-keys": {
					Type: environschema.Tstring,
				},
			},
		},
		config: map[string]interface{}{
			"authorized-keys-path": filepath.Join(home, "key.pub"),
		},
		expectConfig: map[string]interface{}{
			"authorized-keys": fakeSSHKey,
		},
	}, {
		about: "attribute from relative path",
		files: map[string]string{
			filepath.Join(jujuHome, "x"): "content",
		},
		jesInfo: params.JESResponse{
			ProviderType: "something",
			Template: environschema.Fields{
				"attr": {
					Type: environschema.Tstring,
				},
			},
		},
		config: map[string]interface{}{
			"attr-path": "x",
		},
		expectConfig: map[string]interface{}{
			"attr": "content",
		},
	}, {
		about: "attribute from home-relative path",
		files: map[string]string{
			filepath.Join(home, "x"): "content",
		},
		jesInfo: params.JESResponse{
			ProviderType: "something",
			Template: environschema.Fields{
				"attr": {
					Type: environschema.Tstring,
				},
			},
		},
		config: map[string]interface{}{
			"attr-path": filepath.Join("~", "x"),
		},
		expectConfig: map[string]interface{}{
			"attr": "content",
		},
	}, {
		about: "attribute from absolute path",
		files: map[string]string{
			filepath.Join(home, "x"): "content",
		},
		jesInfo: params.JESResponse{
			ProviderType: "something",
			Template: environschema.Fields{
				"attr": {
					Type: environschema.Tstring,
				},
			},
		},
		config: map[string]interface{}{
			"attr-path": filepath.Join(home, "x"),
		},
		expectConfig: map[string]interface{}{
			"attr": "content",
		},
	}, {
		about: "empty file is an error",
		files: map[string]string{
			filepath.Join(jujuHome, "x"): "",
		},
		jesInfo: params.JESResponse{
			ProviderType: "something",
			Template: environschema.Fields{
				"attr": {
					Type: environschema.Tstring,
				},
			},
		},
		config: map[string]interface{}{
			"attr-path": "x",
		},
		expectError: `cannot get value for "x": file ".*home/ubuntu/.juju/x" is empty`,
	}, {
		about: "attribute from path ignored with non-string template entry",
		jesInfo: params.JESResponse{
			ProviderType: "something",
			Template: environschema.Fields{
				"attr": {
					Type: environschema.Tint,
				},
			},
		},
		config: map[string]interface{}{
			"attr-path": "nomatter",
		},
		expectConfig: map[string]interface{}{
			"attr-path": "nomatter",
		},
	}, {
		about: "provider default",
		jesInfo: params.JESResponse{
			ProviderType: "test",
			Template: environschema.Fields{
				"testattr": {
					Type: environschema.Tstring,
				},
			},
		},
		expectConfig: map[string]interface{}{
			"testattr": "testattr-default-value",
		},
	}, {
		about: "provider default error",
		jesInfo: params.JESResponse{
			ProviderType: "test",
			Template: environschema.Fields{
				"testattr-error": {
					Type: environschema.Tstring,
				},
			},
		},
		expectError: `cannot make default value for "testattr-error": an error`,
	}}
	s.PatchValue(&providerDefaults, map[string]map[string]func(*createCommand) (interface{}, error){
		"test": {
			"testattr": func(*createCommand) (interface{}, error) {
				return "testattr-default-value", nil
			},
			"testattr-error": func(*createCommand) (interface{}, error) {
				return "", errgo.New("an error")
			},
		},
	})
	for i, test := range tests {
		c.Logf("test %d: %s", i, test.about)

		for path, contents := range test.files {
			err := os.MkdirAll(filepath.Dir(path), 0777)
			c.Assert(err, gc.IsNil)
			err = ioutil.WriteFile(path, []byte(contents), 0666)
			c.Assert(err, gc.IsNil)
		}
		for name, val := range test.envVars {
			os.Setenv(name, val)
		}

		var createCmd createCommand
		createCmd.envPath.Name = params.Name(test.envName)

		config := make(map[string]interface{})
		for name, val := range test.config {
			config[name] = val
		}
		err := createCmd.setConfigDefaults(config, &test.jesInfo)
		if test.expectError != "" {
			c.Assert(err, gc.ErrorMatches, test.expectError)
		} else {
			c.Assert(err, gc.IsNil)
			c.Assert(config, jc.DeepEquals, test.expectConfig)
		}

		// Remove the test files.
		for path := range test.files {
			err := os.Remove(path)
			c.Assert(err, gc.IsNil)
		}
		for name := range test.envVars {
			os.Setenv(name, "")
		}
	}
}

const fakeSSHKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcEHVJtQyjN0eaNMAQIwhwknKj+8uZCqmzeA6EfnUEsrOHisoKjRVzb3bIRVgbK3SJ2/1yHPpL2WYynt3LtToKgp0Xo7LCsspL2cmUIWNYCbcgNOsT5rFeDsIDr9yQito8A3y31Mf7Ka7Rc0EHtCW4zC5yl/WZjgmMmw930+V1rDa5GjkqivftHE5AvLyRGvZJPOLH8IoO+sl02NjZ7dRhniBO9O5UIwxSkuGA5wvfLV7dyT/LH56gex7C2fkeBkZ7YGqTdssTX6DvFTHjEbBAsdWd8/rqXWtB6Xdi8sb3+aMpg9DRomZfb69Y+JuqWTUaq+q30qG2CTiqFRbgwRpp bob@somewhere\n"