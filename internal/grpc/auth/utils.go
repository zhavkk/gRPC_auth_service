package auth

import (
	"context"
	"log/slog"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zhavkk/gRPC_auth_service/internal/grpc/interceptors"
	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	jwt_ "github.com/zhavkk/gRPC_auth_service/internal/pkg/jwt"
)

const errInvalidToken = "invalid token"

func GetClaimsFromContext(ctx context.Context) (jwt.MapClaims, error) {
	logger.Log.Debug("GetClaimsFromContext: Attempting to get claims from context",
		"expected_key_type",
		interceptors.ClaimsKey)
	val := ctx.Value(interceptors.ClaimsKey)
	if val == nil {
		logger.Log.Warn("GetClaimsFromContext: Value not found in context for key (interceptors.ClaimsKey)")
		valStrKey := ctx.Value("claims")
		if valStrKey != nil {
			logger.Log.Warn("GetClaimsFromContext: Found value using string key claims - indicates key type mismatch",
				"value_type",
				slog.AnyValue(valStrKey).Kind().String())
		} else {
			logger.Log.Warn("GetClaimsFromContext: Value also not found using string key claims")
		}
		return nil, status.Error(codes.Unauthenticated, errInvalidToken)
	}

	claims, ok := val.(jwt.MapClaims)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, errInvalidToken)
	}
	logger.Log.Debug("GetClaimsFromContext: Claims successfully retrieved from context")
	return claims, nil
}

func GetUserIDFromContext(ctx context.Context) (string, error) {
	claims, err := GetClaimsFromContext(ctx)
	if err != nil {
		return "", err
	}

	userID, ok := claims[jwt_.ClaimUUID].(string)
	if !ok || userID == "" {
		logger.Log.Warn("GetUserIDFromContext: UserID not found in claims or not a string/empty",
			slog.Any("claims", claims))
		return "", status.Error(codes.Unauthenticated, errInvalidToken)
	}
	return userID, nil
}

func GetRoleFromContext(ctx context.Context) (string, error) {
	claims, err := GetClaimsFromContext(ctx)
	if err != nil {
		return "", err
	}

	logger.Log.Debug("GetRoleFromContext: Extracted claims", slog.Any("claims", claims))
	role, ok := claims[jwt_.ClaimRole].(string)
	if !ok || role == "" {
		logger.Log.Warn("GetRoleFromContext: Role not found in claims or not a string/empty",
			slog.Any("claims", claims))
		return "", status.Error(codes.Unauthenticated, errInvalidToken)
	}
	return role, nil
}
