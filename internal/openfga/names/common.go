// Copyright 2024 Canonical.

package names

import (
	"github.com/canonical/jimm/v3/pkg/names"
)

// WithAssigneeRelation is a convenience function for role tags to return the tag's string
// with an assignee relation, commonly used when assigning role relations.
func WithAssigneeRelation(groupTag names.RoleTag) string {
	return groupTag.String() + "#" + AssigneeRelation.String()
}
