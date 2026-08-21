package geo

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDownloadIfChangedUsesConditionalHeadersAndContentHash(t *testing.T) {
	var mu sync.Mutex
	body := []byte("database-v1")
	etag := `"v1"`
	conditionalRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if request.Header.Get("If-None-Match") == etag {
			conditionalRequests++
			writer.WriteHeader(http.StatusNotModified)
			return
		}
		writer.Header().Set("ETag", etag)
		_, _ = writer.Write(body)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "GeoLite2-City.mmdb")
	options := resolverOptions{path: path, url: server.URL, client: server.Client(), open: fakeDatabaseOpener(nil)}
	changed, err := downloadIfChanged(context.Background(), options)
	if err != nil || !changed {
		t.Fatalf("first download = %t, %v; want changed", changed, err)
	}
	changed, err = downloadIfChanged(context.Background(), options)
	if err != nil || changed {
		t.Fatalf("conditional download = %t, %v; want unchanged", changed, err)
	}
	if conditionalRequests != 1 {
		t.Fatalf("conditional requests = %d, want 1", conditionalRequests)
	}

	mu.Lock()
	body = []byte("database-v2")
	etag = `"v2"`
	mu.Unlock()
	changed, err = downloadIfChanged(context.Background(), options)
	if err != nil || !changed {
		t.Fatalf("changed download = %t, %v; want changed", changed, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "database-v2" {
		t.Fatalf("database content = %q, %v", got, err)
	}
}

func TestDownloadIfChangedSkipsRenameForIdenticalContent(t *testing.T) {
	body := []byte("same-database")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("ETag", `"new-etag"`)
		_, _ = writer.Write(body)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "GeoLite2-City.mmdb")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat before: %v", err)
	}
	changed, err := downloadIfChanged(context.Background(), resolverOptions{
		path: path, url: server.URL, client: server.Client(), open: fakeDatabaseOpener(nil),
	})
	if err != nil || changed {
		t.Fatalf("download = %t, %v; want unchanged", changed, err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat after: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("identical database content was replaced")
	}
}

func TestResolverRefreshSwapsDatabaseAndClosesPrevious(t *testing.T) {
	var mu sync.Mutex
	body := []byte("1")
	etag := `"1"`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if request.Header.Get("If-None-Match") == etag {
			writer.WriteHeader(http.StatusNotModified)
			return
		}
		writer.Header().Set("ETag", etag)
		_, _ = writer.Write(body)
	}))
	defer server.Close()

	var closes atomic.Int32
	path := filepath.Join(t.TempDir(), "GeoLite2-City.mmdb")
	resolver, err := openResolver(resolverOptions{
		path: path, url: server.URL, interval: time.Hour, client: server.Client(),
		open: fakeDatabaseOpener(&closes), autoUpdate: true,
	})
	if err != nil {
		t.Fatalf("openResolver: %v", err)
	}
	defer resolver.Close()
	point, found := resolver.Lookup(netip.MustParseAddr("8.8.8.8"))
	if !found || point.Latitude != 1 {
		t.Fatalf("initial Lookup = %+v, %t", point, found)
	}

	mu.Lock()
	body = []byte("2")
	etag = `"2"`
	mu.Unlock()
	if err := resolver.refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	point, found = resolver.Lookup(netip.MustParseAddr("8.8.8.8"))
	if !found || point.Latitude != 2 {
		t.Fatalf("refreshed Lookup = %+v, %t", point, found)
	}
	if closes.Load() < 2 { // validation DBs and the replaced active DB are closed.
		t.Fatalf("database closes = %d, want at least 2", closes.Load())
	}
}

func TestAutoResolverUsesCachedDatabaseWhenRefreshFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "GeoLite2-City.mmdb")
	if err := os.WriteFile(path, []byte("3"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	resolver, err := openResolver(resolverOptions{
		path: path, url: server.URL, interval: time.Hour, client: server.Client(),
		open: fakeDatabaseOpener(nil), autoUpdate: true,
	})
	if err != nil {
		t.Fatalf("openResolver with cache: %v", err)
	}
	defer resolver.Close()
	point, found := resolver.Lookup(netip.MustParseAddr("8.8.8.8"))
	if !found || point.Latitude != 3 {
		t.Fatalf("cached Lookup = %+v, %t", point, found)
	}
}

func fakeDatabaseOpener(closes *atomic.Int32) func(string) (*Database, error) {
	return func(path string) (*Database, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var latitude float64
		if _, err := fmt.Sscanf(string(data), "%f", &latitude); err != nil {
			// Download tests use arbitrary content and only need validation success.
			latitude = 1
		}
		longitude := 0.0
		return newDatabase(func(_ netip.Addr, record *locationRecord) (bool, error) {
			record.Location.Latitude = &latitude
			record.Location.Longitude = &longitude
			return true, nil
		}, func() error {
			if closes != nil {
				closes.Add(1)
			}
			return nil
		}), nil
	}
}
