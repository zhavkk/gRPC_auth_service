package app

import (
	"log/slog"
	"time"

	grpcapp "github.com/zhavkk/gRPC_auth_service/internal/app/grpc"
)

type App struct {
	GRPCsrv *grpcapp.App
}

func New(log *slog.Logger, grpcPort int, dsn string, tokenTTL time.Duration) *App {
	//TODO: init storage

	//TODO: init auth service

	//TODO: init gRPC

	gRPCApp := grpcapp.New(log, grpcPort)

	return &App{
		GRPCsrv: gRPCApp,
	}
}
