// Copyright 2020 Canonical Ltd.

// Package db contains routines to store and retrieve data from a database.
package db

import (
	"context"
	"fmt"
	"sync/atomic"

	"gorm.io/gorm"

	"github.com/CanonicalLtd/jimm/internal/dbmodel"
	"github.com/CanonicalLtd/jimm/internal/errors"
)

// A Database provides access to the database model. A Database instance
// is safe to use from multiple goroutines.
type Database struct {
	// DB contains the gorm database storing the data.
	DB *gorm.DB

	// migrated holds whether the database has been successfully migrated
	// to the current database version. The value of migrated should always
	// be read using atomic.LoadUint32 and will contain a 0 if the
	// migration is yet to be run, or 1 if it has been run successfully.
	migrated uint32
}

// Transaction starts a new transaction using the database. This allows
// a set of changes to be performed as a single atomic unit. All of the
// transaction steps should be performed in the given function, if this
// function returns an error then all changes in the transaction will be
// aborted and the error returned. Transactions may be nested.
//
// Attempting to start a transaction on an unmigrated database will result
// in an error with a code of errors.CodeUpgradeInProgress.
func (d *Database) Transaction(f func(*Database) error) error {
	if err := d.ready(); err != nil {
		return err
	}
	return d.DB.Transaction(func(tx *gorm.DB) error {
		d := *d
		d.DB = tx
		return f(&d)
	})
}

// Migrate migrates the configured database to have the structure required
// by the current data model. Unless forced the migration will only be
// performed if there is either no current database, or the major version
// of the current database is the same as the target database. If the
// current database is incompatible then an error with a code of
// errors.CodeServerConfiguration will be returned. If force is requested
// then the migration will be performed no matter what the current version
// is. The force parameter should only be set when the migration is
// initiated by a user request.
func (d *Database) Migrate(ctx context.Context, force bool) error {
	const op = errors.Op("db.Migrate")
	if d == nil || d.DB == nil {
		return errors.E(op, errors.CodeServerConfiguration, "database not configured")
	}
	db := d.DB.WithContext(ctx)
	if err := db.AutoMigrate(&dbmodel.Version{}); err != nil {
		return errors.E(op, dbError(err))
	}
	v := dbmodel.Version{Component: dbmodel.Component}
	if err := db.FirstOrCreate(&v).Error; err != nil {
		return errors.E(op, dbError(err))
	}
	if dbmodel.Major == v.Major && dbmodel.Minor <= v.Minor {
		// The database is already at, or past, our current version.
		// Nothing to do.
		atomic.StoreUint32(&d.migrated, 1)
		return nil
	}
	if v.Major != dbmodel.Major && !force && v.Major != 0 {
		return errors.E(op, errors.CodeServerConfiguration, fmt.Sprintf("database has incompatible version %d.%d", v.Major, v.Minor))
	}

	// The major versions are unchanged, the database can be migrated.
	err := db.AutoMigrate(
		&dbmodel.Application{},
		&dbmodel.ApplicationOffer{},
		&dbmodel.Cloud{},
		&dbmodel.CloudCredential{},
		&dbmodel.CloudRegion{},
		&dbmodel.CloudRegionControllerPriority{},
		&dbmodel.Controller{},
		&dbmodel.Machine{},
		&dbmodel.Model{},
		&dbmodel.Unit{},
		&dbmodel.User{},
		&dbmodel.UserApplicationOfferAccess{},
		&dbmodel.ApplicationOfferRemoteSpace{},
		&dbmodel.ApplicationOfferRemoteEndpoint{},
		&dbmodel.ApplicationOfferConnection{},
		&dbmodel.UserCloudAccess{},
		&dbmodel.UserModelAccess{},
	)
	if err != nil {
		return errors.E(op, dbError(err))
	}

	v.Major = dbmodel.Major
	v.Minor = dbmodel.Minor
	if err := db.Save(&v).Error; err != nil {
		return errors.E(op, dbError(err))
	}
	atomic.StoreUint32(&d.migrated, 1)
	return nil
}

// ready checks that the database is ready to accept requests. An error is
// returned if the database is not yet initialised.
func (d *Database) ready() error {
	if d == nil || d.DB == nil {
		return errors.E(errors.CodeServerConfiguration, "database not configured")
	}
	if atomic.LoadUint32(&d.migrated) == 0 {
		return errors.E(errors.CodeUpgradeInProgress)
	}
	return nil
}