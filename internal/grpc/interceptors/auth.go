package interceptors

import (
	"context"

	"github.com/zhavkk/gRPC_auth_service/internal/lib/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type AuthInterceptor struct {
	secret string
}

func NewAuthInterceptor(secret string) grpc.UnaryServerInterceptor {
	return (&AuthInterceptor{secret: secret}).Unary
}

func (i *AuthInterceptor) Unary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	authHeader := md.Get("authorization")
	if len(authHeader) == 0 {
		return nil, status.Error(codes.Unauthenticated, "authorization token is not provided")
	}

	tokenString := authHeader[0]
	if len(tokenString) < 7 || tokenString[:7] != "Bearer " {
		return nil, status.Error(codes.Unauthenticated, "invalid token format")
	}
	tokenString = tokenString[7:]

	claims, err := jwt.ValidateToken(tokenString, i.secret)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	ctx = context.WithValue(ctx, "claims", claims)

	return handler(ctx, req)
}
