// Package geo performs local MaxMind database lookups.
package geo

import (
	"fmt"
	"math"
	"net/netip"
	"sync"

	"git.gosuda.org/lemon-mint/proxygen/internal/model"
	"github.com/oschwald/maxminddb-golang/v2"
)

// Database is a closeable local geographic database.
type Database struct {
	lifecycle sync.RWMutex
	lookup    locationLookup
	close     func() error
	closed    bool

	closeOnce sync.Once
	closeErr  error
}

type locationRecord struct {
	Location struct {
		Latitude  *float64 `maxminddb:"latitude"`
		Longitude *float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

type locationLookup func(netip.Addr, *locationRecord) (bool, error)

// Open opens the MaxMind database at path.
func Open(path string) (*Database, error) {
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open geo database: %w", err)
	}

	return newDatabase(func(addr netip.Addr, record *locationRecord) (bool, error) {
		result := reader.Lookup(addr)
		if err := result.Err(); err != nil {
			return false, err
		}
		if !result.Found() {
			return false, nil
		}
		if err := result.Decode(record); err != nil {
			return false, err
		}
		return true, nil
	}, reader.Close), nil
}

func newDatabase(lookup locationLookup, close func() error) *Database {
	return &Database{lookup: lookup, close: close}
}

// Lookup returns the geographic location associated with addr. It reports
// false for invalid addresses, unknown addresses, unreadable records, and
// records without valid latitude and longitude values.
func (db *Database) Lookup(addr netip.Addr) (model.GeoPoint, bool) {
	if !addr.IsValid() || addr.Zone() != "" {
		return model.GeoPoint{}, false
	}
	addr = addr.Unmap()

	db.lifecycle.RLock()
	defer db.lifecycle.RUnlock()
	if db.closed {
		return model.GeoPoint{}, false
	}

	var record locationRecord
	found, err := db.lookup(addr, &record)
	if err != nil || !found || !validLocation(record) {
		return model.GeoPoint{}, false
	}
	return model.GeoPoint{
		Latitude:  *record.Location.Latitude,
		Longitude: *record.Location.Longitude,
	}, true
}

func validLocation(record locationRecord) bool {
	latitude := record.Location.Latitude
	longitude := record.Location.Longitude
	if latitude == nil || longitude == nil {
		return false
	}
	return !math.IsNaN(*latitude) && !math.IsInf(*latitude, 0) &&
		!math.IsNaN(*longitude) && !math.IsInf(*longitude, 0) &&
		*latitude >= -90 && *latitude <= 90 &&
		*longitude >= -180 && *longitude <= 180
}

// Close releases the database. Concurrent and repeated calls wait for and
// return the result of the single underlying close operation.
func (db *Database) Close() error {
	db.closeOnce.Do(func() {
		db.lifecycle.Lock()
		defer db.lifecycle.Unlock()

		db.closed = true
		db.closeErr = db.close()
	})
	return db.closeErr
}
