// Package service реализует бизнес-логику сервиса авторизации.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/models"
	"github.com/zhavkk/gRPC_auth_service/internal/pkg/jwt"
	"github.com/zhavkk/gRPC_auth_service/internal/repository/postgres"
	"github.com/zhavkk/gRPC_auth_service/internal/storage"
)

type AuthService struct {
	userRepo  postgres.UserRepository
	jwtConfig jwt.Config
	txManager storage.TxManagerInterface
}

func NewAuthService(
	userRepo postgres.UserRepository,
	jwtConfig jwt.Config,
	txManager storage.TxManagerInterface,
) *AuthService {
	return &AuthService{
		userRepo:  userRepo,
		jwtConfig: jwtConfig,
		txManager: txManager,
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
		logger.Log.Error("Failed to get user by email", "err", err)
		return nil, fmt.Errorf("%s %w", op, ErrInvalidEmailOrPassword)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PassHash), []byte(password)); err != nil {
		logger.Log.Error("Failed to compare password", "err", err)
		return nil, fmt.Errorf("%s %w", op, ErrInvalidEmailOrPassword)
	}

	token, err := jwt.NewToken(*user, s.jwtConfig)
	if err != nil {
		logger.Log.Error("Failed to generate token", "err", err)
		return nil, fmt.Errorf("%s %w", op, ErrFailedToGenerateToken)
	}
	logger.Log.With(slog.String("op", op)).Info("User logged in")
	return &models.LoginResponse{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Role:     user.Role,
		Token:    token,
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
