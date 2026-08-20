package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"git.sepolia.gosuda.org/lemon-mint/proxygen/internal/config"
)

var errRuntimeUnavailable = errors.New("normal mode unavailable: proxy runtime is not wired")

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
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

	if _, err := config.Load(*configPath); err != nil {
		return err
	}
	if *check {
		_, err := fmt.Fprintln(stdout, "configuration is valid")
		return err
	}
	return errRuntimeUnavailable
}
