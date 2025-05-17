// Package service реализует бизнес-логику сервиса авторизации.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	goRedis "github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/models"
	"github.com/zhavkk/gRPC_auth_service/internal/pkg/jwt"
	"github.com/zhavkk/gRPC_auth_service/internal/storage"
)

type RefreshTokenRepository interface {
	StoreRefreshToken(ctx context.Context, userID string, tokenJTI string, ttl time.Duration) error
	GetRefreshTokenJTI(ctx context.Context, userID string) (string, error)
	DeleteRefreshToken(ctx context.Context, userID string) error
}

type UserRepository interface {
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
	UpdateUserRole(ctx context.Context, id string, role string) error
	UpdateUserPassword(ctx context.Context, id string, hashedPassword string) error
}

type AuthService struct {
	userRepo         UserRepository
	jwtConfig        jwt.Config
	txManager        storage.TxManagerInterface
	refreshTokenRepo RefreshTokenRepository
}

func NewAuthService(
	userRepo UserRepository,
	jwtConfig jwt.Config,
	txManager storage.TxManagerInterface,
	refreshTokenRepo RefreshTokenRepository,
) *AuthService {
	return &AuthService{
		userRepo:         userRepo,
		jwtConfig:        jwtConfig,
		txManager:        txManager,
		refreshTokenRepo: refreshTokenRepo,
	}
}

func (s *AuthService) Register(
	ctx context.Context,
	username string,
	email string,
	password string,
	gender bool,
	country string,
	age int32,
	role string,
) (*models.RegisterResponse, error) {
	const op = "auth_service.Register"

	resp := &models.RegisterResponse{}
	err := s.txManager.RunSerializable(ctx, func(ctx context.Context) error {
		_, err := s.userRepo.GetUserByEmail(ctx, email)
		if err == nil {
			return ErrUserAlreadyExists
		}

		PassHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			logger.Log.Error("Failed to generate password hash", "err", err)
			return fmt.Errorf("%s %w", op, ErrHashPassword)
		}

		user := &models.User{
			ID:       uuid.New().String(),
			Username: username,
			Email:    email,
			PassHash: string(PassHash),
			Gender:   gender,
			Country:  country,
			Age:      age,
			Role:     role,
		}

		if err := s.userRepo.CreateUser(ctx, user); err != nil {
			logger.Log.Error("Failed to create user", "err", err)
			return fmt.Errorf("%s %w", op, ErrFailedToCreateUser)
		}

		resp = &models.RegisterResponse{
			ID: user.ID,
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%s %w", op, err)
	}

	logger.Log.With(slog.String("op", op)).Info("user register  successfully")
	return resp, nil
}

func (s *AuthService) Login(
	ctx context.Context,
	email string,
	password string,
) (*models.LoginResponse, error) {
	const op = "auth_service.Login"

	user, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		logger.Log.Error("Failed to get user by email", slog.String("op", op), slog.String("email", email), "err", err)
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, fmt.Errorf("%s: %w", op, ErrInvalidEmailOrPassword)
		}
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGetUser)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PassHash), []byte(password)); err != nil {
		logger.Log.Warn("Invalid password attempt", slog.String("op", op), slog.String("email", email), "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidEmailOrPassword)
	}

	accessToken, err := jwt.NewAccessToken(*user, s.jwtConfig)
	if err != nil {
		logger.Log.Error("Failed to generate access token",
			slog.String("op", op), slog.String("user_id", user.ID), "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGenerateToken)
	}

	refreshTokenJTI := uuid.New().String()
	refreshToken, err := jwt.NewRefreshToken(user.ID, refreshTokenJTI, s.jwtConfig)
	if err != nil {
		logger.Log.Error("Failed to generate refresh token",
			slog.String("op", op), slog.String("user_id", user.ID), "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGenerateToken)
	}

	err = s.refreshTokenRepo.StoreRefreshToken(ctx, user.ID, refreshTokenJTI, s.jwtConfig.RefreshTokenTTL)
	if err != nil {
		logger.Log.Error("Failed to store refresh token JTI in Redis",
			slog.String("op", op), slog.String("user_id", user.ID), "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToStoreToken)
	}

	logger.Log.Info("User logged in successfully", slog.String("op", op), slog.String("user_id", user.ID))
	return &models.LoginResponse{
		ID:           user.ID,
		Username:     user.Username,
		Email:        user.Email,
		Role:         user.Role,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *AuthService) SetUserRole(
	ctx context.Context,
	id string,
	role string,
) (*models.SetUserRoleResponse, error) {
	const op = "auth_service.SetUserRole"

	resp := &models.SetUserRoleResponse{}
	err := s.txManager.RunSerializable(ctx, func(ctx context.Context) error {
		user, err := s.userRepo.GetUserByID(ctx, id)
		if err != nil {
			if errors.Is(err, models.ErrUserNotFound) {
				return fmt.Errorf("%s %w", op, ErrUserNotFound)
			}
			logger.Log.Error("Failed to get user", "err", err)
			return fmt.Errorf("%s %w", op, ErrFailedToGetUser)
		}

		if !isValidRole(role) {
			logger.Log.Error("Invalid role", "err", err)
			return fmt.Errorf("%s %w", op, ErrInvalidRole)
		}

		if err := s.userRepo.UpdateUserRole(ctx, id, role); err != nil {
			logger.Log.Error("Failed to update user role", "err", err)
			return fmt.Errorf("%s %w", op, ErrFailedToUpdateRole)
		}
		logger.Log.With(slog.String("op", op)).Info("User role was updated")
		resp = &models.SetUserRoleResponse{
			ID:   user.ID,
			Role: role,
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%s %w", op, err)
	}

	return resp, nil
}

func (s *AuthService) GetUser(
	ctx context.Context,
	id string,
) (*models.GetUserResponse, error) {
	const op = "auth_service.GetUser"

	user, err := s.userRepo.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			logger.Log.Error("User not found", "err", err)
			return nil, fmt.Errorf("%s %w", op, ErrUserNotFound)
		}
		logger.Log.Error("Failed to get user", "err", err)
		return nil, fmt.Errorf("%s %w", op, ErrFailedToGetUser)
	}

	logger.Log.With(slog.String("op", op)).Info("user found successfully")
	return &models.GetUserResponse{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Gender:   user.Gender,
		Country:  user.Country,
		Age:      user.Age,
		Role:     user.Role,
	}, nil
}

func (s *AuthService) UpdateUser(
	ctx context.Context,
	id string,
	username string,
	country string,
	age int32,
) (*models.UpdateUserResponse, error) {
	const op = "auth_service.UpdateUser"

	resp := &models.UpdateUserResponse{}
	err := s.txManager.RunSerializable(ctx, func(ctx context.Context) error {
		user, err := s.userRepo.GetUserByID(ctx, id)
		if err != nil {
			logger.Log.Error("Failed to get user", "err", err)
			return fmt.Errorf("%s %w", op, ErrFailedToGetUser)
		}

		user.Username = username
		user.Country = country
		user.Age = age

		if err := s.userRepo.UpdateUser(ctx, user); err != nil {
			logger.Log.Error("Failed to update user", "err", err)
			return fmt.Errorf("%s %w", op, ErrFailedToUpdateUser)
		}

		logger.Log.With(slog.String("op", op)).Info("User was updated")
		resp = &models.UpdateUserResponse{
			ID:       user.ID,
			Username: user.Username,
			Email:    user.Email,
			Gender:   user.Gender,
			Country:  user.Country,
			Age:      user.Age,
			Role:     user.Role,
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%s %w", op, err)
	}
	return resp, nil
}

func (s *AuthService) ChangePassword(
	ctx context.Context,
	id string,
	oldPassword string,
	newPassword string,
) (*models.ChangePasswordResponse, error) {
	const op = "auth_service.ChangePassword"

	resp := &models.ChangePasswordResponse{}
	err := s.txManager.RunSerializable(ctx, func(ctx context.Context) error {
		user, err := s.userRepo.GetUserByID(ctx, id)
		if err != nil {
			logger.Log.Error("Failed to get user", "err", err)
			return fmt.Errorf("%s %w", op, ErrFailedToGetUser)
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.PassHash), []byte(oldPassword)); err != nil {
			return fmt.Errorf("%s %w", op, ErrInvalidPassword)
		}

		PassHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			logger.Log.Error("Failed to generate password hash", "err", err)
			return fmt.Errorf("%s %w", op, ErrHashPassword)
		}

		if err := s.userRepo.UpdateUserPassword(ctx, id, string(PassHash)); err != nil {
			logger.Log.Error("Failed to update user password", "err", err)
			return fmt.Errorf("%s %w", op, ErrFailedToUpdatePassword)
		}
		logger.Log.With(slog.String("op", op)).Info("Pass was changed")
		resp = &models.ChangePasswordResponse{
			Success: true,
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%s %w", op, err)
	}
	return resp, nil
}

func isValidRole(role string) bool {
	validRoles := map[string]bool{
		"user":   true,
		"admin":  true,
		"artist": true,
	}
	return validRoles[role]
}

func (s *AuthService) RefreshToken(
	ctx context.Context,
	oldRefreshTokenString string,
) (*models.RefreshTokenResponse, error) {
	const op = "auth_service.RefreshToken"

	userID, jtiFromToken, err := jwt.ParseAndValidateRefreshToken(oldRefreshTokenString, s.jwtConfig)
	if err != nil {
		logger.Log.Warn("Invalid refresh token received for refresh", "op", op, "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidRefreshToken)
	}

	jtiFromRedis, err := s.refreshTokenRepo.GetRefreshTokenJTI(ctx, userID)
	if err != nil {
		if errors.Is(err, goRedis.Nil) {
			logger.Log.Warn("Refresh token JTI not found in Redis (token revoked or expired)",
				slog.String("op", op), slog.String("user_id", userID))
			return nil, fmt.Errorf("%s: %w", op, ErrTokenNotFound)
		}
		logger.Log.Error("Failed to get refresh token JTI from Redis", "op", op, "user_id", userID, "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGetRefreshTokenJTI)
	}

	if jtiFromRedis != jtiFromToken {
		logger.Log.Warn("JTI mismatch for refresh token (potential replay attack or old token)",
			slog.String("op", op), slog.String("user_id", userID))
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidRefreshToken)
	}

	err = s.refreshTokenRepo.DeleteRefreshToken(ctx, userID)
	if err != nil {
		logger.Log.Error("Failed to delete old refresh token JTI from Redis during refresh",
			slog.String("op", op), slog.String("user_id", userID), "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToDeleteRefreshToken)
	}

	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		logger.Log.Error("Failed to get user for new token generation during refresh",
			slog.String("op", op), slog.String("user_id", userID), "err", err)
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGetUser)
	}

	newAccessToken, err := jwt.NewAccessToken(*user, s.jwtConfig)
	if err != nil {
		logger.Log.Error("Failed to generate new access token during refresh", "op", op, "user_id", user.ID, "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGenerateToken)
	}

	newJTI := uuid.New().String()
	newRefreshToken, err := jwt.NewRefreshToken(userID, newJTI, s.jwtConfig)
	if err != nil {
		logger.Log.Error("Failed to generate new refresh token during refresh",
			slog.String("op", op), slog.String("user_id", user.ID), "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGenerateToken)
	}

	err = s.refreshTokenRepo.StoreRefreshToken(ctx, userID, newJTI, s.jwtConfig.RefreshTokenTTL)
	if err != nil {
		logger.Log.Error("Failed to store new refresh token JTI in Redis during refresh",
			slog.String("op", op), slog.String("user_id", user.ID), "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToStoreToken)
	}

	logger.Log.Info("Token refreshed successfully", "op", op, "user_id", userID)
	return &models.RefreshTokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (s *AuthService) Logout(
	ctx context.Context,
	refreshToken string,
) (*models.LogoutResponse, error) {
	const op = "auth_service.Logout"

	userID, _, err := jwt.ParseAndValidateRefreshToken(refreshToken, s.jwtConfig)
	if err != nil {
		logger.Log.Warn("Invalid refresh token received for logout", "op", op, "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidRefreshToken)
	}

	err = s.refreshTokenRepo.DeleteRefreshToken(ctx, userID)
	if err != nil {
		logger.Log.Error("Failed to delete refresh token from Redis", "op", op, "user_id", userID, "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToDeleteRefreshToken)
	}

	return &models.LogoutResponse{
		Success: true,
		Message: "Logout successful",
	}, nil
}
