package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zhavkk/gRPC_auth_service/internal/domain"
	"github.com/zhavkk/gRPC_auth_service/internal/lib/jwt"
	"github.com/zhavkk/gRPC_auth_service/internal/repository/mocks"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthService_Register(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)

	config := jwt.Config{
		Secret:   "secret",
		TokenTTL: 1 * time.Second,
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	authService := NewAuthService(mockRepo, log, config)

	t.Run("success", func(t *testing.T) {
		// Настраиваем ожидания мока
		mockRepo.EXPECT().
			GetUserByEmail(gomock.Any(), "test@test.com").
			Return(nil, errors.New("user not found"))

		mockRepo.EXPECT().
			CreateUser(gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, user *domain.User) error {
				assert.Equal(t, "test", user.Username)
				assert.Equal(t, "test@test.com", user.Email)
				assert.Equal(t, "Russia", user.Country)
				assert.Equal(t, int32(20), user.Age)
				assert.Equal(t, "user", user.Role)
				return nil
			})

		response, err := authService.Register(context.Background(), "test", "test@test.com", "password123", true, "Russia", 20)
		assert.NoError(t, err)
		assert.NotEmpty(t, response.ID)
	})

	t.Run("duplicate email", func(t *testing.T) {
		existingUser := &domain.User{
			ID:       "existing-id",
			Email:    "test@test.com",
			Username: "existing",
		}
		mockRepo.EXPECT().
			GetUserByEmail(gomock.Any(), "test@test.com").
			Return(existingUser, nil)

		_, err := authService.Register(context.Background(), "test2", "test@test.com", "password123", true, "Russia", 20)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user with this email already exists")
	})
}

func TestAuthService_Login(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)

	config := jwt.Config{
		Secret:   "secret",
		TokenTTL: 1 * time.Second,
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	authService := NewAuthService(mockRepo, log, config)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)

	user := &domain.User{
		ID:       "test-id",
		Email:    "test@test.com",
		Username: "test",
		Role:     "user",
		PassHash: string(hashedPassword),
	}

	t.Run("success", func(t *testing.T) {
		mockRepo.EXPECT().
			GetUserByEmail(gomock.Any(), "test@test.com").
			Return(user, nil)

		response, err := authService.Login(context.Background(), "test@test.com", "password123")
		assert.NoError(t, err)
		assert.NotEmpty(t, response.Token)
		assert.Equal(t, user.ID, response.ID)
		assert.Equal(t, user.Email, response.Email)
		assert.Equal(t, user.Username, response.Username)
		assert.Equal(t, user.Role, response.Role)
	})

	t.Run("user not found", func(t *testing.T) {
		mockRepo.EXPECT().
			GetUserByEmail(gomock.Any(), "notfound@test.com").
			Return(nil, errors.New("user not found"))

		_, err := authService.Login(context.Background(), "notfound@test.com", "password123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid email or password")
	})

	t.Run("wrong password", func(t *testing.T) {
		mockRepo.EXPECT().
			GetUserByEmail(gomock.Any(), "test@test.com").
			Return(user, nil)

		_, err := authService.Login(context.Background(), "test@test.com", "wrongpassword")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid email or password")
	})
}
func TestAuthService_ChangePassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)

	config := jwt.Config{
		Secret:   "secret",
		TokenTTL: 1 * time.Second,
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	authService := NewAuthService(mockRepo, log, config)

	oldPassword := "old-password"
	hashedOldPassword, _ := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.DefaultCost)

	user := &domain.User{
		ID:       "user-id",
		Username: "test",
		Email:    "test@test.com",
		PassHash: string(hashedOldPassword),
		Role:     "user",
	}

	t.Run("success", func(t *testing.T) {
		mockRepo.EXPECT().
			GetUserByID(gomock.Any(), "user-id").
			Return(user, nil)

		mockRepo.EXPECT().
			UpdateUserPassword(gomock.Any(), "user-id", gomock.Any()).
			Return(nil)

		resp, err := authService.ChangePassword(context.Background(), "user-id", oldPassword, "new-password123")
		assert.NoError(t, err)
		assert.True(t, resp.Success)
	})

	t.Run("wrong old password", func(t *testing.T) {
		mockRepo.EXPECT().
			GetUserByID(gomock.Any(), "user-id").
			Return(user, nil)

		_, err := authService.ChangePassword(context.Background(), "user-id", "wrong-old-password", "new-password123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid old password")
	})

	t.Run("user not found", func(t *testing.T) {
		mockRepo.EXPECT().
			GetUserByID(gomock.Any(), "not-exist").
			Return(nil, errors.New("user not found"))

		_, err := authService.ChangePassword(context.Background(), "not-exist", oldPassword, "new-password123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")
	})
}

func TestAuthService_SetUserRole(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)

	config := jwt.Config{
		Secret:   "secret",
		TokenTTL: 1 * time.Second,
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	authService := NewAuthService(mockRepo, log, config)

	user := &domain.User{
		ID:       "user-id",
		Username: "test",
		Email:    "test@test.com",
		Role:     "user",
	}

	t.Run("success", func(t *testing.T) {
		mockRepo.EXPECT().
			GetUserByID(gomock.Any(), "user-id").
			Return(user, nil)

		mockRepo.EXPECT().
			UpdateUserRole(gomock.Any(), "user-id", "admin").
			Return(nil)

		resp, err := authService.SetUserRole(context.Background(), "user-id", "admin")
		assert.NoError(t, err)
		assert.Equal(t, "user-id", resp.ID)
		assert.Equal(t, "admin", resp.Role)
	})

	t.Run("user not found", func(t *testing.T) {
		mockRepo.EXPECT().
			GetUserByID(gomock.Any(), "not-exist").
			Return(nil, errors.New("user not found"))

		_, err := authService.SetUserRole(context.Background(), "not-exist", "admin")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")
	})

	t.Run("update error", func(t *testing.T) {
		mockRepo.EXPECT().
			GetUserByID(gomock.Any(), "user-id").
			Return(user, nil)

		mockRepo.EXPECT().
			UpdateUserRole(gomock.Any(), "user-id", "admin").
			Return(errors.New("db error"))

		_, err := authService.SetUserRole(context.Background(), "user-id", "admin")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to update user role")
	})
}

func TestAuthService_GetUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)

	config := jwt.Config{
		Secret:   "secret",
		TokenTTL: 1 * time.Second,
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	authService := NewAuthService(mockRepo, log, config)

	user := &domain.User{
		ID:       "user-id",
		Username: "test",
		Email:    "test@test.com",
		Role:     "user",
	}
	t.Run("success", func(t *testing.T) {
		mockRepo.EXPECT().
			GetUserByID(gomock.Any(), "user-id").
			Return(user, nil)

		resp, err := authService.GetUser(context.Background(), "user-id")
		assert.NoError(t, err)
		assert.Equal(t, user.ID, resp.ID)
		assert.Equal(t, user.Username, resp.Username)
		assert.Equal(t, user.Email, resp.Email)
		assert.Equal(t, user.Role, resp.Role)
	})

	t.Run("user not found", func(t *testing.T) {
		mockRepo.EXPECT().
			GetUserByID(gomock.Any(), "not-exist").
			Return(nil, errors.New("user not found"))

		_, err := authService.GetUser(context.Background(), "not-exist")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")
	})
}

func TestAuthService_UpdateUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)

	config := jwt.Config{
		Secret:   "secret",
		TokenTTL: 1 * time.Second,
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	authService := NewAuthService(mockRepo, log, config)

	user := &domain.User{
		ID:       "111",
		Username: "test",
		Email:    "test@test.com",
		Role:     "user",
	}

	t.Run("success", func(t *testing.T) {
		mockRepo.EXPECT().
			GetUserByID(gomock.Any(), "111").
			Return(user, nil)

		mockRepo.EXPECT().
			UpdateUser(gomock.Any(), gomock.Any()).
			Return(nil)

		_, err := authService.UpdateUser(context.Background(), user.ID, "new-username", "new-email", int32(20))

		assert.NoError(t, err)
		assert.Equal(t, "new-username", user.Username)
	})

	t.Run("user not found", func(t *testing.T) {
		mockRepo.EXPECT().
			GetUserByID(gomock.Any(), "not-exist").
			Return(nil, errors.New("user not found"))

		_, err := authService.UpdateUser(context.Background(), "not-exist", "new-username", "new-email", int32(20))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")
	})
}
