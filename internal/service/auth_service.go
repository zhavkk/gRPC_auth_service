package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/zhavkk/gRPC_auth_service/internal/domain"
	"github.com/zhavkk/gRPC_auth_service/internal/repository/postgres"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	userRepo postgres.UserRepository
}

func NewAuthService(userRepo postgres.UserRepository) *AuthService {
	return &AuthService{
		userRepo: userRepo,
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
) (*domain.RegisterResponse, error) {
	_, err := s.userRepo.GetUserByEmail(ctx, email)
	if err == nil {
		return nil, errors.New("user with this email already exists")
	}

	PassHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &domain.User{
		ID:       uuid.New().String(),
		Username: username,
		Email:    email,
		PassHash: string(PassHash),
		Gender:   gender,
		Country:  country,
		Age:      age,
		Role:     "user",
	}

	if err := s.userRepo.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &domain.RegisterResponse{
		ID: user.ID,
	}, nil
}

func (s *AuthService) Login(
	ctx context.Context,
	email string,
	password string,
) (*domain.LoginResponse, error) {
	user, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, errors.New("invalid email or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PassHash), []byte(password)); err != nil {
		return nil, errors.New("invalid email or password")
	}

	// TODO: JWT token
	token := "dummy-token"

	return &domain.LoginResponse{
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
) (*domain.SetUserRoleResponse, error) {
	user, err := s.userRepo.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if !isValidRole(role) {
		return nil, errors.New("invalid role")
	}

	if err := s.userRepo.UpdateUserRole(ctx, id, role); err != nil {
		return nil, fmt.Errorf("failed to update user role: %w", err)
	}

	return &domain.SetUserRoleResponse{
		ID:   user.ID,
		Role: role,
	}, nil
}

func (s *AuthService) GetUser(
	ctx context.Context,
	id string,
) (*domain.GetUserResponse, error) {
	user, err := s.userRepo.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return &domain.GetUserResponse{
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
) (*domain.UpdateUserResponse, error) {
	user, err := s.userRepo.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}

	user.Username = username
	user.Country = country
	user.Age = age

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return &domain.UpdateUserResponse{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Gender:   user.Gender,
		Country:  user.Country,
		Age:      user.Age,
		Role:     user.Role,
	}, nil
}

func (s *AuthService) ChangePassword(
	ctx context.Context,
	id string,
	oldPassword string,
	newPassword string,
) (*domain.ChangePasswordResponse, error) {
	user, err := s.userRepo.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PassHash), []byte(oldPassword)); err != nil {
		return nil, errors.New("invalid old password")
	}

	PassHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	if err := s.userRepo.UpdateUserPassword(ctx, id, string(PassHash)); err != nil {
		return nil, fmt.Errorf("failed to update password: %w", err)
	}

	return &domain.ChangePasswordResponse{
		Success: true,
	}, nil
}

func isValidRole(role string) bool {
	validRoles := map[string]bool{
		"user":   true,
		"admin":  true,
		"artist": true,
	}
	return validRoles[role]
}
