// Package app управляет жизненным циклом приложения, включая инициализацию зависимостей.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/joho/godotenv"

	grpcapp "github.com/zhavkk/gRPC_auth_service/internal/app/grpc"
	"github.com/zhavkk/gRPC_auth_service/internal/config"
	"github.com/zhavkk/gRPC_auth_service/internal/grpc/auth"
	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/pkg/jwt"
	"github.com/zhavkk/gRPC_auth_service/internal/repository/postgres"
	redisRepo "github.com/zhavkk/gRPC_auth_service/internal/repository/redis"
	"github.com/zhavkk/gRPC_auth_service/internal/service"
	"github.com/zhavkk/gRPC_auth_service/internal/storage"
)

type App struct {
	GRPCsrv *grpcapp.App
	Storage *storage.Storage
	Redis   *storage.RedisClient
}

func SetupApplication() (*config.Config, error) {
	if err := godotenv.Load(); err != nil {
		return nil, fmt.Errorf("error loading .env file: %w", err)
	}

	cfg := config.MustLoad()
	logger.Init(cfg.Env)

	return cfg, nil
}

func StartApplication(ctx context.Context, cfg *config.Config) error {
	logger.Log.Info("starting app", slog.Any("env", cfg))

	application, err := New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize application: %w", err)
	}

	grpcErrChan := make(chan error, 1)

	go func() {
		if err := application.GRPCsrv.Run(); err != nil {
			logger.Log.Error("gRPC server failed during run", "error", err)
			grpcErrChan <- err
			close(grpcErrChan)
		}
	}()

	select {
	case <-ctx.Done():
		logger.Log.Info("shutting down application due to signal.", slog.String("reason", ctx.Err().Error()))
	case err := <-grpcErrChan:
		logger.Log.Error("gRPC server stopped with error, shutting down application", "error", err)
		shutdownCtxErr, cancelShutdownErr := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelShutdownErr()
		if shutdownErr := application.Shutdown(shutdownCtxErr); shutdownErr != nil {
			logger.Log.Error("error during application shutdown after gRPC failure",
				slog.String("shutdown_error", shutdownErr.Error()),
				slog.String("original_grpc_error", err.Error()))
		}
		return fmt.Errorf("gRPC server failed: %w", err)
	}

	logger.Log.Info("starting graceful shutdown")
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelShutdown()

	if err := application.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("application shutdown failed: %w", err)
	}

	logger.Log.Info("application stopped successfully")
	return nil
}

func New(ctx context.Context, cfg *config.Config) (*App, error) {
	jwtConfig := jwt.Config{
		Secret:          cfg.JWTSecret,
		AccessTokenTTL:  cfg.AccessTokenTTL,
		RefreshTokenTTL: cfg.RefreshTokenTTL,
	}

	db, err := storage.NewStorage(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	redisClient, err := storage.NewRedisClient(ctx, &cfg.Redis)
	if err != nil {
		return nil, fmt.Errorf("failed to create redis client: %w", err)
	}

	userRepo := postgres.NewUserRepository(db)
	txManager, err := storage.NewTxManager(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create tx manager: %w", err)
	}

	tokenRepo := redisRepo.NewRefreshTokenRepoRedis(redisClient)

	profileRepo := postgres.NewProfileRepository(db)
	artistRepo := postgres.NewArtistRepository(db)
	authService := service.NewAuthService(userRepo, profileRepo, artistRepo, jwtConfig, txManager, tokenRepo)

	gRPCApp := grpcapp.New(cfg.GRPC.Port, jwtConfig)
	auth.Register(gRPCApp.GetServer(), authService)

	return &App{
		GRPCsrv: gRPCApp,
		Storage: db,
		Redis:   redisClient,
	}, nil
}

func (a *App) Shutdown(ctx context.Context) error {
	logger.Log.Info("stopping gRPC server...")
	a.GRPCsrv.Stop()

	logger.Log.Info("closing database connection...")
	if err := a.Storage.Close(); err != nil {
		return fmt.Errorf("failed to close database storage: %w", err)
	}

	logger.Log.Info("closing redis connection...")
	if err := a.Redis.GetRedis().Close(); err != nil {
		return fmt.Errorf("failed to close redis connection: %w", err)
	}

	logger.Log.Info("application components stopped")
	return nil
}
