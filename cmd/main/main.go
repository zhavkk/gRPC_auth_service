// Package main является точкой входа для сервиса аутентификации.
package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"

	"github.com/zhavkk/gRPC_auth_service/internal/app"
	"github.com/zhavkk/gRPC_auth_service/internal/config"
	"github.com/zhavkk/gRPC_auth_service/internal/logger"
)

func main() {
	if err := godotenv.Load(); err != nil {
		logger.Log.Error("Error loading .env file", "error", err)
		os.Exit(1)
	}
	cfg := config.MustLoad()

	logger.Init(cfg.Env)

	logger.Log.Info("starting app", slog.Any("env", cfg))
	application := app.New(cfg.GRPC.Port, cfg.TokenTTL)

	go func() {
		application.GRPCsrv.MustRun()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	marker := <-stop

	logger.Log.Info("stopping application ", slog.String("signal: ", marker.String()))

	application.GRPCsrv.Stop()

	logger.Log.Info("application stopped successfully")
}
