package main

import (
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"
	"github.com/zhavkk/gRPC_auth_service/internal/app"
	"github.com/zhavkk/gRPC_auth_service/internal/config"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
		os.Exit(1)
	}
	cfg := config.MustLoad()

	//TODO: logger

	log := setupLogger(cfg.Env)

	log.Info("starting app", slog.Any("env", cfg))
	//TODO: application
	application := app.New(log, cfg.GRPC.Port, cfg.TokenTTL)

	//TODO: run gRPC
	go func() {
		application.GRPCsrv.MustRun()
	}()

	//Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	marker := <-stop

	log.Info("stopping application ", slog.String("signal: ", marker.String()))

	application.GRPCsrv.Stop()

	log.Info("application stopped sucessfully")
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger
	switch env {
	case envLocal:
		log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	case envDev:
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	case envProd:
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	}
	return log
}
