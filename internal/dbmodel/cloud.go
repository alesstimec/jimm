// Copyright 2020 Canonical Ltd.

package dbmodel

import (
	"github.com/juju/names/v4"
	"gorm.io/gorm"
)

// A Cloud represents a cloud service.
type Cloud struct {
	gorm.Model

	// Name is the name of the cloud.
	Name string `gorm:"not null;uniqueIndex"`

	// Type is the provider type of cloud.
	Type string `gorm:"not null"`

	// HostCloudRegion is the "cloud/region" that hosts this cloud, if the
	// cloud is hosted.
	HostCloudRegion string

	// AuthTypes is the authentication types supported by this cloud.
	AuthTypes Strings

	// Endpoint is the API endpoint URL for the cloud.
	Endpoint string

	// IdentityEndpoint is the API endpoint URL of the cloud identity
	// service.
	IdentityEndpoint string

	// StorageEndpoint is the API endpoint URL of the cloud storage
	// service.
	StorageEndpoint string

	// Regions contains the regions associated with this cloud.
	Regions []CloudRegion

	// CACertificates contains the CA Certificates associated with this
	// cloud.
	CACertificates Strings

	// Config contains the configuration associated with this cloud.
	Config Map

	// Users contains the users that are authorized on this cloud.
	Users []UserCloudAccess
}

// Tag returns a names.Tag for this cloud.
func (c Cloud) Tag() names.Tag {
	return names.NewCloudTag(c.Name)
}

// SetTag sets the name of the cloud to the value from the given cloud tag.
func (c *Cloud) SetTag(t names.CloudTag) {
	c.Name = t.Id()
}

// Region returns the cloud region with the given name. If there is no
// such region a zero valued region is returned.
func (c Cloud) Region(name string) CloudRegion {
	for _, r := range c.Regions {
		if r.Name == name {
			return r
		}
	}
	return CloudRegion{}
}

// A CloudRegion is a region of a cloud.
type CloudRegion struct {
	gorm.Model

	// Cloud is the cloud this region belongs to.
	CloudID uint `gorm:"uniqueIndex:idx_cloud_region_cloud_id_name"`
	Cloud   Cloud

	// Name is the name of the region.
	Name string `gorm:"not null;uniqueIndex:idx_cloud_region_cloud_id_name"`

	// Endpoint is the API endpoint URL for the region.
	Endpoint string

	// IdentityEndpoint is the API endpoint URL of the region identity
	// service.
	IdentityEndpoint string

	// StorageEndpoint is the API endpoint URL of the region storage
	// service.
	StorageEndpoint string

	// Config contains the configuration associated with this region.
	Config Map

	// Controllers contains any controllers that can provide service for
	// this cloud-region.
	Controllers []CloudRegionControllerPriority
}

// A UserCloudAccess maps the access level of a user on a cloud.
type UserCloudAccess struct {
	gorm.Model

	// User is the User this access is for.
	UserID uint
	User   User

	// Cloud is the Cloud this access is for.
	CloudID uint
	Cloud   Cloud

	// Access is the access level of the user on the cloud.
	Access string `gorm:"not null"`
}
