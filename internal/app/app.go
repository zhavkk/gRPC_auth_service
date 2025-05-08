// Package app управляет жизненным циклом приложения, включая инициализацию зависимостей.
package app

import (
	"context"
	"os"
	"time"

	grpcapp "github.com/zhavkk/gRPC_auth_service/internal/app/grpc"
	"github.com/zhavkk/gRPC_auth_service/internal/config"
	"github.com/zhavkk/gRPC_auth_service/internal/grpc/auth"
	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/pkg/jwt"
	"github.com/zhavkk/gRPC_auth_service/internal/repository/postgres"
	"github.com/zhavkk/gRPC_auth_service/internal/service"
	"github.com/zhavkk/gRPC_auth_service/internal/storage"
)

type App struct {
	GRPCsrv *grpcapp.App
}

func New(grpcPort int, tokenTTL time.Duration) *App {
	jwtConfig := jwt.Config{
		Secret:   os.Getenv("JWT_SECRET"),
		TokenTTL: tokenTTL,
	}

	dbConfig := &config.Config{
		DBURL: os.Getenv("DB_URL"),
	}

	db, err := storage.NewStorage(context.Background(), dbConfig)
	if err != nil {
		logger.Log.Error("failed to create storage", "error", err)
		os.Exit(1)
	}

	userRepo := postgres.NewUserRepository(db)
	txManager, err := storage.NewTxManager(context.Background(), dbConfig)
	if err != nil {
		logger.Log.Error("failed to create tx manager", "error", err)
		os.Exit(1)
	}
	authService := service.NewAuthService(userRepo, jwtConfig, txManager)

	gRPCApp := grpcapp.New(grpcPort)
	auth.Register(gRPCApp.GetServer(), authService)

	return &App{
		GRPCsrv: gRPCApp,
	}
}
