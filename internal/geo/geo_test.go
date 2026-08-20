package geo

import (
	"errors"
	"net/netip"
	"path/filepath"
	"testing"

	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/model"
)

func TestOpenRejectsInvalidPath(t *testing.T) {
	database, err := Open(filepath.Join(t.TempDir(), "missing.mmdb"))
	if err == nil {
		_ = database.Close()
		t.Fatal("Open() succeeded for a missing database")
	}
	if database != nil {
		t.Fatal("Open() returned a database with an error")
	}
}

func TestLookupRejectsInvalidAddress(t *testing.T) {
	lookupCalled := false
	database := newDatabase(func(netip.Addr, *locationRecord) (bool, error) {
		lookupCalled = true
		return true, nil
	}, func() error { return nil })
	t.Cleanup(func() { _ = database.Close() })

	if point, found := database.Lookup(netip.Addr{}); found || point != (model.GeoPoint{}) {
		t.Fatalf("Lookup(invalid) = (%+v, %t), want zero point, false", point, found)
	}
	if lookupCalled {
		t.Fatal("Lookup(invalid) called the database lookup seam")
	}
}

func TestLookupFoundUnknownAndEmptyRecords(t *testing.T) {
	foundAddress := netip.MustParseAddr("192.0.2.1")
	emptyAddress := netip.MustParseAddr("192.0.2.2")
	unknownAddress := netip.MustParseAddr("192.0.2.3")

	database := newDatabase(func(addr netip.Addr, record *locationRecord) (bool, error) {
		switch addr {
		case foundAddress:
			latitude, longitude := 51.5074, -0.1278
			record.Location.Latitude = &latitude
			record.Location.Longitude = &longitude
			return true, nil
		case emptyAddress:
			return true, nil
		default:
			return false, nil
		}
	}, func() error { return nil })
	t.Cleanup(func() { _ = database.Close() })

	if point, found := database.Lookup(foundAddress); !found || point != (model.GeoPoint{Latitude: 51.5074, Longitude: -0.1278}) {
		t.Fatalf("Lookup(found) = (%+v, %t), want London, true", point, found)
	}
	if point, found := database.Lookup(unknownAddress); found || point != (model.GeoPoint{}) {
		t.Fatalf("Lookup(unknown) = (%+v, %t), want zero point, false", point, found)
	}
	if point, found := database.Lookup(emptyAddress); found || point != (model.GeoPoint{}) {
		t.Fatalf("Lookup(empty) = (%+v, %t), want zero point, false", point, found)
	}
}

func TestCloseCallsReaderExactlyOnce(t *testing.T) {
	closeError := errors.New("close failed")
	closeCalls := 0
	lookupCalls := 0
	database := newDatabase(func(netip.Addr, *locationRecord) (bool, error) {
		lookupCalls++
		return false, nil
	}, func() error {
		closeCalls++
		return closeError
	})

	if err := database.Close(); !errors.Is(err, closeError) {
		t.Fatalf("first Close() error = %v, want %v", err, closeError)
	}
	if err := database.Close(); !errors.Is(err, closeError) {
		t.Fatalf("second Close() error = %v, want %v", err, closeError)
	}
	if closeCalls != 1 {
		t.Fatalf("underlying close calls = %d, want 1", closeCalls)
	}
	if _, found := database.Lookup(netip.MustParseAddr("192.0.2.1")); found {
		t.Fatal("Lookup() after Close() reported a record")
	}
	if lookupCalls != 0 {
		t.Fatalf("lookup calls after Close() = %d, want 0", lookupCalls)
	}
}
