package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Warky-Devs/WkMailSync/pkg/config"
	"github.com/Warky-Devs/WkMailSync/pkg/monitor"
)

func runMonitor(cfg *config.Config) {
	if cfg.Monitor == nil {
		log.Fatal("monitor mode requires a monitor: section in the config file")
	}
	if cfg.Monitor.Source.Host == "" {
		log.Fatal("monitor.source.host is required")
	}
	if cfg.Monitor.OutputDir == "" {
		log.Fatal("monitor.output_dir is required")
	}
	if cfg.Monitor.Source.OAuth2 == nil && cfg.Monitor.Source.Password == "" {
		log.Fatal("monitor.source requires either oauth2: credentials or a password:")
	}

	engine := monitor.New(cfg.Monitor)

	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received %s — shutting down…", sig)
		cancel()
	}()

	if err := engine.Run(ctx); err != nil {
		log.Fatalf("monitor error: %v", err)
	}
}
