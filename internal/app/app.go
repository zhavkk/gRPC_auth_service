// Package app управляет жизненным циклом приложения, включая инициализацию зависимостей.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/joho/godotenv"

	grpcapp "github.com/zhavkk/gRPC_auth_service/internal/app/grpc"
	"github.com/zhavkk/gRPC_auth_service/internal/config"
	"github.com/zhavkk/gRPC_auth_service/internal/grpc/auth"
	"github.com/zhavkk/gRPC_auth_service/internal/kafka/producer"
	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/outbox"
	"github.com/zhavkk/gRPC_auth_service/internal/pkg/jwt"
	"github.com/zhavkk/gRPC_auth_service/internal/repository/postgres"
	redisRepo "github.com/zhavkk/gRPC_auth_service/internal/repository/redis"
	"github.com/zhavkk/gRPC_auth_service/internal/service"
	"github.com/zhavkk/gRPC_auth_service/internal/storage"
)

type App struct {
	GRPCsrv      *grpcapp.App
	Storage      *storage.Storage
	Redis        *storage.RedisClient
	kafkaProd    producer.KafkaProducer
	outboxWorker *outbox.Worker
}

func SetupApplication() (*config.Config, error) {
	if err := godotenv.Load(); err != nil {
		return nil, fmt.Errorf("error loading .env file: %w", err)
	}

	cfg := config.MustLoad()
	logger.Init(cfg.Env)

	return cfg, nil
}

func StartApplication(parentCtx context.Context, cfg *config.Config) error {
	logger.Log.Info("starting app", slog.Any("env", cfg))
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	var wg sync.WaitGroup
	application, err := New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize application: %w", err)
	}

	grpcErrChan := make(chan error, 1)

	wg.Add(1)
	go func() {
		defer wg.Done()
		application.outboxWorker.Start(ctx)
	}()
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
		cancel()
		wg.Wait()
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
	wg.Wait()
	logger.Log.Info("all workers stopped, proceeding with application shutdown")
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

	txManager, err := storage.NewTxManager(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create tx manager: %w", err)
	}

	userRepo := postgres.NewUserRepository(db)
	tokenRepo := redisRepo.NewRefreshTokenRepoRedis(redisClient)
	profileRepo := postgres.NewProfileRepository(db)
	artistRepo := postgres.NewArtistRepository(db)
	outboxRepo := postgres.NewOutboxRepository(db, txManager)

	kafkaProd, err := producer.NewSaramaProducer(&cfg.Kafka, cfg.Kafka.Topics, outboxRepo)
	if err != nil {
		return nil, fmt.Errorf("failed to init kafka producer: %w", err)
	}
	worker := outbox.NewWorker(
		outboxRepo,
		kafkaProd,
		cfg.Outbox.BatchSize,
		cfg.Outbox.PollInterval,
	)

	authService := service.NewAuthService(
		userRepo,
		profileRepo,
		artistRepo,
		jwtConfig,
		txManager,
		tokenRepo,
		outboxRepo,
		cfg.Kafka.Topics,
	)

	gRPCApp := grpcapp.New(cfg.GRPC.Port, jwtConfig)
	auth.Register(gRPCApp.GetServer(), authService)

	return &App{
		GRPCsrv:      gRPCApp,
		Storage:      db,
		Redis:        redisClient,
		kafkaProd:    kafkaProd,
		outboxWorker: worker,
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

	logger.Log.Info("closing kafka producer")
	a.kafkaProd.Close()

	logger.Log.Info("application components stopped")
	return nil
}
