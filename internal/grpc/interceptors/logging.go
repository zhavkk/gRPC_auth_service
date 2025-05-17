package interceptors

import (
	"context"
	"time"

	"google.golang.org/grpc"

	"github.com/zhavkk/gRPC_auth_service/internal/logger"
)

type LoggingInterceptor struct {
}

func NewLoggingInterceptor() grpc.UnaryServerInterceptor {
	return (&LoggingInterceptor{}).Unary
}

func (i *LoggingInterceptor) Unary(ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	start := time.Now()

	logger.Log.Debug("starting to handle request",
		"method", info.FullMethod,
		"request", req,
	)

	resp, err := handler(ctx, req)

	duration := time.Since(start)
	if err != nil {
		logger.Log.Debug("request failed",
			"method", info.FullMethod,
			"duration", duration,
			"error", err,
		)
	} else {
		logger.Log.Debug("request completed",
			"method", info.FullMethod,
			"duration", duration,
			"response", resp,
		)
	}

	return resp, err
}
