package interceptors

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc"
)

type LoggingInterceptor struct {
	log *slog.Logger
}

func NewLoggingInterceptor(log *slog.Logger) grpc.UnaryServerInterceptor {
	return (&LoggingInterceptor{log: log}).Unary
}

func (i *LoggingInterceptor) Unary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	start := time.Now()

	i.log.Debug("starting to handle request",
		"method", info.FullMethod,
		"request", req,
	)

	resp, err := handler(ctx, req)

	duration := time.Since(start)
	if err != nil {
		i.log.Error("request failed",
			"method", info.FullMethod,
			"duration", duration,
			"error", err,
		)
	} else {
		i.log.Debug("request completed",
			"method", info.FullMethod,
			"duration", duration,
			"response", resp,
		)
	}

	return resp, err
}
