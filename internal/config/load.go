package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Load reads a JSON configuration, imports optional WireGuard files relative
// to the JSON file, and validates the merged result.
func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	cfg, err := decode(file)
	if err != nil {
		return Config{}, fmt.Errorf("config %q: %w", path, err)
	}
	if cfg.WireGuardDirectory != "" {
		if err := validateControlBytes("wireguard_directory", cfg.WireGuardDirectory); err != nil {
			return Config{}, fmt.Errorf("config %q: %w", path, err)
		}
		if err := validateEndpoint("wireguard_health_check_address", cfg.WireGuardHealthCheckAddress); err != nil {
			return Config{}, fmt.Errorf("config %q: %w", path, err)
		}
		directory := cfg.WireGuardDirectory
		if !filepath.IsAbs(directory) {
			directory = filepath.Join(filepath.Dir(path), directory)
		}
		edges, err := loadWireGuardDirectory(directory, cfg.WireGuardHealthCheckAddress)
		if err != nil {
			return Config{}, fmt.Errorf("load WireGuard directory: %w", err)
		}
		cfg.Edges = append(cfg.Edges, edges...)
		cfg.WireGuardDirectory = ""
		cfg.WireGuardHealthCheckAddress = ""
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("config %q: validate: %w", path, err)
	}
	return cfg, nil
}

// Decode strictly decodes and validates an inline-only configuration.
// Directory-backed configurations require Load so relative paths have a base.
func Decode(reader io.Reader) (Config, error) {
	cfg, err := decode(reader)
	if err != nil {
		return Config{}, err
	}
	if cfg.WireGuardDirectory != "" {
		return Config{}, fmt.Errorf("wireguard_directory requires loading from a file path")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate: %w", err)
	}
	return cfg, nil
}

func decode(reader io.Reader) (Config, error) {
	cfg := Default()
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode JSON: %w", err)
	}

	var trailing json.RawMessage
	err := decoder.Decode(&trailing)
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, fmt.Errorf("decode JSON: multiple JSON values are not allowed")
		}
		return Config{}, fmt.Errorf("decode trailing JSON: %w", err)
	}
	return cfg, nil
}
