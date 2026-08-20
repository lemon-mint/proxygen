package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// Load reads, strictly decodes, defaults, and validates a configuration file.
func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	cfg, err := Decode(file)
	if err != nil {
		return Config{}, fmt.Errorf("config %q: %w", path, err)
	}
	return cfg, nil
}

// Decode strictly decodes one JSON object, applies defaults to omitted scalar
// fields, and validates the resulting configuration.
func Decode(reader io.Reader) (Config, error) {
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

	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate: %w", err)
	}
	return cfg, nil
}
