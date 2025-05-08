// Package interceptors содержит middleware для gRPC-сервера, включая аутентификацию и логирование.
package interceptors

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/zhavkk/gRPC_auth_service/internal/pkg/jwt"
)

type AuthInterceptor struct {
	jwtConfig jwt.Config
}

func NewAuthInterceptor(jwtConfig jwt.Config) grpc.UnaryServerInterceptor {
	return (&AuthInterceptor{jwtConfig: jwtConfig}).Unary
}

var publicMethods = map[string]bool{
	"/auth.Auth/Register": true,
	"/auth.Auth/Login":    true,
}

type contextKey string

const claimsKey contextKey = "claims"

var (
	ErrInvalidToken              = status.Error(codes.Unauthenticated, "invalid token")
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
		return nil, ErrInvalidTokenMetadata
	}

	authHeader := md.Get("authorization")
	if len(authHeader) == 0 {
		return nil, ErrInvalidTokenAuthorization
	}

	tokenString := authHeader[0]
	if !strings.HasPrefix(tokenString, "Bearer ") {
		return nil, ErrInvalidTokenFormat
	}

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	claims, err := jwt.ValidateToken(tokenString, i.jwtConfig)
	if err != nil {
		return nil, ErrInvalidToken
	}
	ctx = context.WithValue(ctx, claimsKey, claims)
	return handler(ctx, req)
}
