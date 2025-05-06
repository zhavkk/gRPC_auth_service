package app

import (
	"context"
	"log/slog"
	"os"
	"time"

	grpcapp "github.com/zhavkk/gRPC_auth_service/internal/app/grpc"
	"github.com/zhavkk/gRPC_auth_service/internal/config"
	"github.com/zhavkk/gRPC_auth_service/internal/grpc/auth"
	"github.com/zhavkk/gRPC_auth_service/internal/lib/jwt"
	"github.com/zhavkk/gRPC_auth_service/internal/repository/postgres"
	"github.com/zhavkk/gRPC_auth_service/internal/service"
	"github.com/zhavkk/gRPC_auth_service/internal/storage"
)

type App struct {
	GRPCsrv *grpcapp.App
}

func New(log *slog.Logger, grpcPort int, tokenTTL time.Duration) *App {
	jwtConfig := jwt.Config{
		Secret:   os.Getenv("JWT_SECRET"),
		TokenTTL: tokenTTL,
	}

	dbConfig := &config.Config{
		DB: config.DB{
			Host:     os.Getenv("DB_HOST"),
			Port:     os.Getenv("DB_PORT"),
			User:     os.Getenv("DB_USER"),
			Password: os.Getenv("DB_PASSWORD"),
			Name:     os.Getenv("DB_NAME"),
		},
	}

	storage, err := storage.NewStorage(context.Background(), dbConfig)
	if err != nil {
		log.Error("failed to create storage", "error", err)
		os.Exit(1)
	}

	userRepo := postgres.NewUserRepository(storage, log)
	authService := service.NewAuthService(userRepo, log, jwtConfig)

	gRPCApp := grpcapp.New(log, grpcPort)
	auth.Register(gRPCApp.GetServer(), authService)

	return &App{
		GRPCsrv: gRPCApp,
	}
}
