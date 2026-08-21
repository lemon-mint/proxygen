package geo

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"git.gosuda.org/lemon-mint/proxygen/internal/model"
)

const (
	// DefaultDatabaseURL is used when geo_database is omitted.
	DefaultDatabaseURL     = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
	DefaultRefreshInterval = 24 * time.Hour
	maxDatabaseBytes       = 256 << 20
)

// Resolver owns a reloadable GeoIP database. Configured local databases are
// static; the default temporary database is conditionally refreshed daily.
type Resolver struct {
	mu sync.RWMutex
	db *Database

	options resolverOptions
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	closeOnce sync.Once
	closeErr  error
}

type resolverOptions struct {
	path       string
	url        string
	interval   time.Duration
	client     *http.Client
	open       func(string) (*Database, error)
	autoUpdate bool
}

type downloadMetadata struct {
	ETag         string `json:"etag"`
	LastModified string `json:"last_modified"`
}

// OpenResolver opens configuredPath when non-empty. Otherwise it maintains the
// default database below os.TempDir and starts a daily conditional downloader.
func OpenResolver(configuredPath string) (*Resolver, error) {
	if configuredPath != "" {
		return openResolver(resolverOptions{path: configuredPath, open: Open})
	}
	path := filepath.Join(os.TempDir(), "proxygen", "GeoLite2-City.mmdb")
	return openResolver(resolverOptions{
		path:       path,
		url:        DefaultDatabaseURL,
		interval:   DefaultRefreshInterval,
		client:     &http.Client{Timeout: 10 * time.Minute},
		open:       Open,
		autoUpdate: true,
	})
}

func openResolver(options resolverOptions) (*Resolver, error) {
	if options.open == nil {
		return nil, errors.New("GeoIP database opener is required")
	}
	if options.autoUpdate {
		if options.client == nil || options.url == "" || options.interval <= 0 {
			return nil, errors.New("automatic GeoIP update options are incomplete")
		}
		if err := os.MkdirAll(filepath.Dir(options.path), 0o700); err != nil {
			return nil, fmt.Errorf("create GeoIP temporary directory: %w", err)
		}
		_, downloadErr := downloadIfChanged(context.Background(), options)
		if downloadErr != nil {
			if _, statErr := os.Stat(options.path); statErr != nil {
				return nil, fmt.Errorf("download default GeoIP database: %w", downloadErr)
			}
		}
	}

	database, err := options.open(options.path)
	if err != nil {
		return nil, err
	}
	resolver := &Resolver{db: database, options: options}
	if options.autoUpdate {
		ctx, cancel := context.WithCancel(context.Background())
		resolver.cancel = cancel
		resolver.wg.Add(1)
		go resolver.updateLoop(ctx)
	}
	return resolver, nil
}

// Lookup implements the edgepool geographic lookup contract.
func (resolver *Resolver) Lookup(address netip.Addr) (model.GeoPoint, bool) {
	resolver.mu.RLock()
	defer resolver.mu.RUnlock()
	if resolver.db == nil {
		return model.GeoPoint{}, false
	}
	return resolver.db.Lookup(address)
}

func (resolver *Resolver) updateLoop(ctx context.Context) {
	defer resolver.wg.Done()
	ticker := time.NewTicker(resolver.options.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = resolver.refresh(ctx)
		}
	}
}

func (resolver *Resolver) refresh(ctx context.Context) error {
	changed, err := downloadIfChanged(ctx, resolver.options)
	if err != nil || !changed {
		return err
	}
	newDatabase, err := resolver.options.open(resolver.options.path)
	if err != nil {
		return fmt.Errorf("open refreshed GeoIP database: %w", err)
	}

	resolver.mu.Lock()
	oldDatabase := resolver.db
	resolver.db = newDatabase
	resolver.mu.Unlock()
	if oldDatabase != nil {
		return oldDatabase.Close()
	}
	return nil
}

// Close stops updates and closes the active memory-mapped database exactly once.
func (resolver *Resolver) Close() error {
	if resolver == nil {
		return nil
	}
	resolver.closeOnce.Do(func() {
		if resolver.cancel != nil {
			resolver.cancel()
		}
		resolver.wg.Wait()
		resolver.mu.Lock()
		database := resolver.db
		resolver.db = nil
		resolver.mu.Unlock()
		if database != nil {
			resolver.closeErr = database.Close()
		}
	})
	return resolver.closeErr
}

func downloadIfChanged(ctx context.Context, options resolverOptions) (bool, error) {
	metadataPath := options.path + ".metadata.json"
	metadata := readDownloadMetadata(metadataPath)
	_, existingErr := os.Stat(options.path)
	hasExisting := existingErr == nil

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, options.url, nil)
	if err != nil {
		return false, err
	}
	if hasExisting {
		if metadata.ETag != "" {
			request.Header.Set("If-None-Match", metadata.ETag)
		}
		if metadata.LastModified != "" {
			request.Header.Set("If-Modified-Since", metadata.LastModified)
		}
	}
	response, err := options.client.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		if !hasExisting {
			return false, errors.New("GeoIP server returned not-modified without a cached database")
		}
		return false, nil
	}
	if response.StatusCode != http.StatusOK {
		return false, fmt.Errorf("GeoIP download returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maxDatabaseBytes {
		return false, fmt.Errorf("GeoIP database exceeds %d bytes", maxDatabaseBytes)
	}

	temporary, err := os.CreateTemp(filepath.Dir(options.path), ".GeoLite2-City-*.mmdb")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	keepTemporary := false
	defer func() {
		_ = temporary.Close()
		if !keepTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return false, err
	}
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(temporary, hasher), io.LimitReader(response.Body, maxDatabaseBytes+1))
	if err != nil {
		return false, err
	}
	if written > maxDatabaseBytes {
		return false, fmt.Errorf("GeoIP database exceeds %d bytes", maxDatabaseBytes)
	}
	if err := temporary.Sync(); err != nil {
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}

	newMetadata := downloadMetadata{ETag: response.Header.Get("ETag"), LastModified: response.Header.Get("Last-Modified")}
	if hasExisting {
		existingHash, hashErr := hashFile(options.path)
		if hashErr == nil && string(existingHash) == string(hasher.Sum(nil)) {
			return false, writeDownloadMetadata(metadataPath, newMetadata)
		}
	}
	validationDatabase, err := options.open(temporaryPath)
	if err != nil {
		return false, fmt.Errorf("validate downloaded GeoIP database: %w", err)
	}
	if err := validationDatabase.Close(); err != nil {
		return false, fmt.Errorf("close validated GeoIP database: %w", err)
	}
	if err := os.Rename(temporaryPath, options.path); err != nil {
		return false, err
	}
	keepTemporary = true
	// Metadata only optimizes the next request. The validated database has
	// already been atomically installed, so a metadata failure must not prevent
	// the active resolver from reloading it.
	_ = writeDownloadMetadata(metadataPath, newMetadata)
	return true, nil
}

func hashFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func readDownloadMetadata(path string) downloadMetadata {
	data, err := os.ReadFile(path)
	if err != nil {
		return downloadMetadata{}
	}
	var metadata downloadMetadata
	if json.Unmarshal(data, &metadata) != nil {
		return downloadMetadata{}
	}
	return metadata
}

func writeDownloadMetadata(path string, metadata downloadMetadata) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".metadata-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
