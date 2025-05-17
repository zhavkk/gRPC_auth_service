// Package main является точкой входа для сервиса аутентификации.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/zhavkk/gRPC_auth_service/internal/app"
	"github.com/zhavkk/gRPC_auth_service/internal/logger"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg, err := app.SetupApplication()
	if err != nil {
		log.Printf("Application setup failed: %v\n", err)
		return 1
	}

	logger.Log.Info("Starting application")

	ctx, stopSignal := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignal()

	if err := app.StartApplication(ctx, cfg); err != nil {
		logger.Log.Error("application run failed", "error", err)
		return 1
	}

	logger.Log.Info("application exited gracefully")
	return 0
}
