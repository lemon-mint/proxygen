package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"git.gosuda.org/lemon-mint/proxygen/internal/config"
)

func TestCheckModeOnlyLoadsConfiguration(t *testing.T) {
	originalLoad := loadConfig
	originalNew := newRuntime
	t.Cleanup(func() {
		loadConfig = originalLoad
		newRuntime = originalNew
	})
	var loadedPath string
	loadConfig = func(path string) (config.Config, error) {
		loadedPath = path
		return config.Config{}, nil
	}
	newRuntime = func(config.Config) (runtime, error) {
		t.Fatal("check mode constructed runtime")
		return nil, nil
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if err := run([]string{"-config", "proxy.json", "-check"}, &stdout, &stderr); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if loadedPath != "proxy.json" {
		t.Fatalf("loaded path = %q, want proxy.json", loadedPath)
	}
	if stdout.String() != "configuration is valid\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestNormalModeRunsAndClosesRuntime(t *testing.T) {
	originalLoad := loadConfig
	originalNew := newRuntime
	t.Cleanup(func() {
		loadConfig = originalLoad
		newRuntime = originalNew
	})
	events := []string{}
	wantConfig := config.Config{MTU: 1420}
	loadConfig = func(path string) (config.Config, error) {
		events = append(events, "load:"+path)
		return wantConfig, nil
	}
	application := &fakeRuntime{events: &events}
	newRuntime = func(got config.Config) (runtime, error) {
		if !reflect.DeepEqual(got, wantConfig) {
			t.Fatalf("newRuntime config = %#v, want %#v", got, wantConfig)
		}
		events = append(events, "construct")
		return application, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := runContext(ctx, []string{"-config", "proxy.json"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("runContext() error = %v", err)
	}
	wantEvents := []string{"load:proxy.json", "construct", "run", "close"}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %v, want %v", events, wantEvents)
	}
}

func TestCheckModeReturnsLoadError(t *testing.T) {
	originalLoad := loadConfig
	t.Cleanup(func() { loadConfig = originalLoad })
	wantErr := errors.New("invalid configuration")
	loadConfig = func(string) (config.Config, error) { return config.Config{}, wantErr }

	err := run([]string{"-config", "proxy.json", "-check"}, &bytes.Buffer{}, &bytes.Buffer{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("run() error = %v, want %v", err, wantErr)
	}
}

type fakeRuntime struct {
	events *[]string
}

func (runtime *fakeRuntime) Run(context.Context) error {
	*runtime.events = append(*runtime.events, "run")
	return nil
}

func (runtime *fakeRuntime) Close() error {
	*runtime.events = append(*runtime.events, "close")
	return nil
}
