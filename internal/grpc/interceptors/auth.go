// Package interceptors содержит middleware для gRPC-сервера, включая аутентификацию и логирование.
package interceptors

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	pkgjwt "github.com/zhavkk/gRPC_auth_service/internal/pkg/jwt"
)

type AuthInterceptor struct {
	jwtConfig pkgjwt.Config
}

func NewAuthInterceptor(jwtConfig pkgjwt.Config) grpc.UnaryServerInterceptor {
	return (&AuthInterceptor{jwtConfig: jwtConfig}).Unary
}

var publicMethods = map[string]bool{
	"/auth.Auth/Register": true,
	"/auth.Auth/Login":    true,
}

type contextKey string

const ClaimsKey = contextKey("claims")

var (
	ErrInvalidTokenFormat        = status.Error(codes.Unauthenticated, "invalid token format")
	ErrInvalidTokenHeader        = status.Error(codes.Unauthenticated, "invalid token header")
	ErrInvalidTokenMetadata      = status.Error(codes.Unauthenticated, "invalid token metadata")
	ErrInvalidTokenAuthorization = status.Error(codes.Unauthenticated, "authorization token is not provided")
)

func (i *AuthInterceptor) Unary(ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	if publicMethods[info.FullMethod] {
		return handler(ctx, req)
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		logger.Log.Warn("AuthInterceptor: Failed to get metadata from context")
		return nil, ErrInvalidTokenMetadata
	}

	authHeader := md.Get("authorization")
	if len(authHeader) == 0 {
		logger.Log.Warn("AuthInterceptor: Authorization header not found")
		return nil, ErrInvalidTokenAuthorization
	}

	tokenString := authHeader[0]
	if !strings.HasPrefix(tokenString, "Bearer ") {
		logger.Log.Warn("AuthInterceptor: Authorization header does not have Bearer prefix", "header", tokenString)
		return nil, ErrInvalidTokenFormat
	}

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	logger.Log.Debug("AuthInterceptor: Attempting to validate token", "token", tokenString)

	claims, err := pkgjwt.ValidateToken(tokenString, i.jwtConfig)
	if err != nil {
		logger.Log.Warn("AuthInterceptor: pkgjwt.ValidateToken failed", "error", err, "token", tokenString)

		if errors.Is(err, pkgjwt.ErrTokenExpired) {
			return nil, status.Error(codes.Unauthenticated, "access token expired")
		}
		if errors.Is(err, pkgjwt.ErrInvalidToken) {
			return nil, status.Error(codes.Unauthenticated, "access token is invalid (specific)")
		}

		return nil, status.Error(codes.Unauthenticated, "token validation error: "+err.Error())
	}

	logger.Log.Debug("AuthInterceptor: Token validated successfully", slog.Any("claims", claims))
	ctx = context.WithValue(ctx, ClaimsKey, claims)
	return handler(ctx, req)
}
