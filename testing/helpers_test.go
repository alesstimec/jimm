// Copyright 2025 Canonical.

package testing

import (
	qt "github.com/frankban/quicktest"
	"github.com/juju/version/v2"
)

// SkipIfControllerAgentVersionGreaterThan skips the test if the model's
// controller agent version is greater than the provided version string.
func SkipIfControllerAgentVersionGreaterThan(c *qt.C, currentVersion string, maxVersion string) {
	c.Helper()
	agentVersion := version.MustParse(currentVersion)
	threshold := version.MustParse(maxVersion)
	if agentVersion.Compare(threshold) > 0 {
		c.Skipf("skipping test: controller agent version %s is greater than %s", agentVersion, threshold)
	}
}
