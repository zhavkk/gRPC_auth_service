// Package redis implements the RefreshTokenRepository interface using Redis.
package redis

import (
	"context"
	"fmt"
	"time"

	goRedis "github.com/redis/go-redis/v9"

	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/storage"
)

type RefreshTokenRepoRedis struct {
	redisClient *storage.RedisClient
}

func NewRefreshTokenRepoRedis(client *storage.RedisClient) *RefreshTokenRepoRedis {
	return &RefreshTokenRepoRedis{redisClient: client}
}

func userRefreshTokenKey(userID string) string {
	return fmt.Sprintf("refresh_jti:%s", userID)
}

func (r *RefreshTokenRepoRedis) StoreRefreshToken(
	ctx context.Context, userID string, tokenJTI string, ttl time.Duration,
) error {
	const op = "redisRepo.StoreRefreshToken"
	key := userRefreshTokenKey(userID)
	err := r.redisClient.GetRedis().Set(ctx, key, tokenJTI, ttl).Err()
	if err != nil {
		logger.Log.Error("Failed to store refresh token JTI", "op", op, "user_id", userID, "err", err)
		return fmt.Errorf("redis: failed to store refresh token JTI for user %s: %w", userID, err)
	}
	return nil
}

func (r *RefreshTokenRepoRedis) GetRefreshTokenJTI(ctx context.Context, userID string) (string, error) {
	key := userRefreshTokenKey(userID)
	jti, err := r.redisClient.GetRedis().Get(ctx, key).Result()
	if err != nil {
		if err == goRedis.Nil {
			logger.Log.Info("Refresh token JTI not found", "user_id", userID)
			return "", err
		}
		logger.Log.Error("Failed to get refresh token JTI", "err", err)
		return "", fmt.Errorf("redis: failed to get refresh token JTI for user %s: %w", userID, err)
	}
	return jti, nil
}

func (r *RefreshTokenRepoRedis) DeleteRefreshToken(ctx context.Context, userID string) error {
	key := userRefreshTokenKey(userID)
	err := r.redisClient.GetRedis().Del(ctx, key).Err()
	if err != nil {
		logger.Log.Error("Failed to delete refresh token JTI", "err", err)
		return fmt.Errorf("redis: failed to delete refresh token JTI for user %s: %w", userID, err)
	}
	logger.Log.Info("Refresh token JTI deleted", "user_id", userID)
	return nil
}
