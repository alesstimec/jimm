// Copyright 2024 Canonical.
package rebac_admin

var (
	NewRoleService        = newRoleService
	NewidentitiesService  = newidentitiesService
	NewResourcesService   = newResourcesService
	NewEntitlementService = newEntitlementService
	EntitlementsList      = entitlementsList
	Capabilities          = capabilities
)

type RolesService = rolesService
