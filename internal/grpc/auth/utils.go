package auth

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const errInvalidToken = "invalid token"

func GetClaimsFromContext(ctx context.Context) (jwt.MapClaims, error) {
	claims, ok := ctx.Value("claims").(jwt.MapClaims)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, errInvalidToken)
	}
	return claims, nil
}

func GetUserIDFromContext(ctx context.Context) (string, error) {
	claims, err := GetClaimsFromContext(ctx)
	if err != nil {
		return "", err
	}

	userID, ok := claims["uuid"].(string)
	if !ok || userID == "" {
		return "", status.Error(codes.Unauthenticated, errInvalidToken)
	}
	return userID, nil
}

func GetRoleFromContext(ctx context.Context) (string, error) {
	claims, err := GetClaimsFromContext(ctx)
	if err != nil {
		return "", err
	}

	role, ok := claims["role"].(string)
	if !ok || role == "" {
		return "", status.Error(codes.Unauthenticated, errInvalidToken)
	}
	return role, nil
}
