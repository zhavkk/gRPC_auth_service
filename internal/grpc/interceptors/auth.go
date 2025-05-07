package interceptors

import (
	"context"
	"strings"

	"github.com/zhavkk/gRPC_auth_service/internal/lib/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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

func (i *AuthInterceptor) Unary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if publicMethods[info.FullMethod] {
		return handler(ctx, req)
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	authHeader := md.Get("authorization")
	if len(authHeader) == 0 {
		return nil, status.Error(codes.Unauthenticated, "authorization token is not provided")
	}

	tokenString := authHeader[0]
	if !strings.HasPrefix(tokenString, "Bearer ") {
		return nil, status.Error(codes.Unauthenticated, "invalid token format")
	}

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	claims, err := jwt.ValidateToken(tokenString, i.jwtConfig)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	ctx = context.WithValue(ctx, "claims", claims)

	return handler(ctx, req)
}
