package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"git.gosuda.org/lemon-mint/proxygen/internal/app"
	"git.gosuda.org/lemon-mint/proxygen/internal/config"
)

type runtime interface {
	Run(context.Context) error
	Close() error
}

var (
	loadConfig = config.Load
	newRuntime = func(cfg config.Config) (runtime, error) {
		return app.New(cfg)
	}
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runContext(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	return runContext(context.Background(), args, stdout, stderr)
}

func runContext(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("proxygen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "path to JSON configuration")
	check := flags.Bool("check", false, "validate configuration and exit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	if *configPath == "" {
		return fmt.Errorf("-config is required")
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	if *check {
		_, err := fmt.Fprintln(stdout, "configuration is valid")
		return err
	}

	application, err := newRuntime(cfg)
	if err != nil {
		return err
	}
	return errors.Join(application.Run(ctx), application.Close())
}
