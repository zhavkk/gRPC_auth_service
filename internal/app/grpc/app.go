package grpcapp

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/zhavkk/gRPC_auth_service/internal/grpc/auth"
	"github.com/zhavkk/gRPC_auth_service/internal/grpc/interceptors"
	"github.com/zhavkk/gRPC_auth_service/internal/lib/jwt"
	"google.golang.org/grpc"
)

type App struct {
	log        *slog.Logger
	gRPCServer *grpc.Server
	port       int
}

func New(log *slog.Logger, port int) *App {
	jwtConfig := jwt.Config{
		Secret:   os.Getenv("JWT_SECRET"),
		TokenTTL: 1 * time.Hour,
	}

	authInterceptor := interceptors.NewAuthInterceptor(jwtConfig)
	loggingInterceptor := interceptors.NewLoggingInterceptor(log)

	gRPCServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			loggingInterceptor,
			authInterceptor,
		),
	)

	var service auth.AuthService
	auth.Register(gRPCServer, service)

	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
	}
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

func (a *App) Run() error {
	const op = "grpcapp.Run" // to logger

	log := a.log.With(slog.String("op", op), slog.Int("port", a.port))

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("grpc server is running ", slog.String("addr", l.Addr().String()))

	if err := a.gRPCServer.Serve(l); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *App) Stop() {
	const op = "grpcapp.Stop"

	a.log.With(slog.String("op", op)).Info("stopping gRPC server", slog.Int("port", a.port))

	a.gRPCServer.GracefulStop()

}
