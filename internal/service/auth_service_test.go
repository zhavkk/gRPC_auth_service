package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"

	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/models"
	"github.com/zhavkk/gRPC_auth_service/internal/pkg/jwt"
	"github.com/zhavkk/gRPC_auth_service/internal/repository/mocks"
)

func TestAuthService_Register(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTx := mocks.NewMockTxManagerInterface(ctrl)
	config := jwt.Config{
		Secret:   "secret",
		TokenTTL: 1 * time.Second,
	}
	authService := NewAuthService(mockRepo, config, mockTx)

	t.Run("success", func(t *testing.T) {
		mockTx.EXPECT().RunSerializable(gomock.Any(),
			gomock.Any(),
		).DoAndReturn(func(ctx context.Context,
			f func(context.Context) error,
		) error {
			return f(ctx)
		})

		mockRepo.EXPECT().GetUserByEmail(gomock.Any(), "test@test.com").Return(nil, ErrUserNotFound)
		mockRepo.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(nil)

		response, err := authService.Register(context.Background(),
			"test",
			"test@test.com",
			"password123",
			true,
			"Russia",
			20,
			"user",
		)
		assert.NoError(t, err)
		assert.NotEmpty(t, response.ID)
	})

	t.Run("duplicate email", func(t *testing.T) {
		mockTx.EXPECT().RunSerializable(gomock.Any(),
			gomock.Any(),
		).DoAndReturn(func(ctx context.Context,
			f func(context.Context) error,
		) error {
			return f(ctx)
		})

		existingUser := &models.User{
			ID:       "existing-id",
			Email:    "test@test.com",
			Username: "existing",
		}
		mockRepo.EXPECT().GetUserByEmail(gomock.Any(),
			"test@test.com",
		).Return(existingUser, nil)

		_, err := authService.Register(context.Background(),
			"test2",
			"test@test.com",
			"password123",
			true,
			"Russia",
			20,
			"user",
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user with this email already exists")
	})
}

func TestAuthService_Login(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTx := mocks.NewMockTxManagerInterface(ctrl)
	config := jwt.Config{
		Secret:   "secret",
		TokenTTL: 1 * time.Second,
	}
	authService := NewAuthService(mockRepo, config, mockTx)

	hashedPassword, _ := bcrypt.GenerateFromPassword(
		[]byte("password123"),
		bcrypt.DefaultCost,
	)

	user := &models.User{
		ID:       "test-id",
		Email:    "test@test.com",
		Username: "test",
		Role:     "user",
		PassHash: string(hashedPassword),
	}

	t.Run("success", func(t *testing.T) {
		mockRepo.EXPECT().GetUserByEmail(gomock.Any(),
			"test@test.com",
		).Return(user, nil)

		response, err := authService.Login(context.Background(),
			"test@test.com",
			"password123",
		)
		assert.NoError(t, err)
		assert.NotEmpty(t, response.Token)
		assert.Equal(t, user.ID, response.ID)
		assert.Equal(t, user.Email, response.Email)
		assert.Equal(t, user.Username, response.Username)
		assert.Equal(t, user.Role, response.Role)
	})

	t.Run("user not found", func(t *testing.T) {
		mockRepo.EXPECT().GetUserByEmail(gomock.Any(),
			"notfound@test.com",
		).Return(nil, ErrUserNotFound)

		_, err := authService.Login(context.Background(),
			"notfound@test.com",
			"password123",
		)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidEmailOrPassword))
	})

	t.Run("wrong password", func(t *testing.T) {
		mockRepo.EXPECT().GetUserByEmail(gomock.Any(),
			"test@test.com",
		).Return(user, nil)

		_, err := authService.Login(context.Background(),
			"test@test.com",
			"wrongpassword",
		)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidEmailOrPassword))
	})
}

func TestAuthService_ChangePassword(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTx := mocks.NewMockTxManagerInterface(ctrl)
	config := jwt.Config{
		Secret:   "secret",
		TokenTTL: 1 * time.Second,
	}
	authService := NewAuthService(mockRepo, config, mockTx)

	oldPassword := "old-password"
	hashedOldPassword, _ := bcrypt.GenerateFromPassword(
		[]byte(oldPassword),
		bcrypt.DefaultCost,
	)

	user := &models.User{
		ID:       "user-id",
		Username: "test",
		Email:    "test@test.com",
		PassHash: string(hashedOldPassword),
		Role:     "user",
	}

	t.Run("success", func(t *testing.T) {
		mockTx.EXPECT().RunSerializable(gomock.Any(),
			gomock.Any(),
		).DoAndReturn(func(ctx context.Context,
			f func(context.Context) error,
		) error {
			return f(ctx)
		})

		mockRepo.EXPECT().GetUserByID(gomock.Any(),
			"user-id",
		).Return(user, nil)
		mockRepo.EXPECT().UpdateUserPassword(gomock.Any(),
			"user-id",
			gomock.Any(),
		).Return(nil)

		resp, err := authService.ChangePassword(context.Background(),
			"user-id",
			oldPassword,
			"new-password123",
		)
		assert.NoError(t, err)
		assert.True(t, resp.Success)
	})
}

func TestAuthService_SetUserRole(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTx := mocks.NewMockTxManagerInterface(ctrl)
	config := jwt.Config{
		Secret:   "secret",
		TokenTTL: 1 * time.Second,
	}
	authService := NewAuthService(mockRepo, config, mockTx)

	user := &models.User{
		ID:       "user-id",
		Username: "test",
		Email:    "test@test.com",
		Role:     "user",
	}

	t.Run("success", func(t *testing.T) {
		mockTx.EXPECT().RunSerializable(gomock.Any(),
			gomock.Any(),
		).DoAndReturn(func(ctx context.Context,
			f func(context.Context) error,
		) error {
			return f(ctx)
		})

		mockRepo.EXPECT().GetUserByID(gomock.Any(), "user-id").Return(user, nil)
		mockRepo.EXPECT().UpdateUserRole(gomock.Any(), "user-id", "admin").Return(nil)

		resp, err := authService.SetUserRole(context.Background(), "user-id", "admin")
		assert.NoError(t, err)
		assert.Equal(t, "user-id", resp.ID)
		assert.Equal(t, "admin", resp.Role)
	})
}

func TestAuthService_GetUser(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTx := mocks.NewMockTxManagerInterface(ctrl)
	config := jwt.Config{
		Secret:   "secret",
		TokenTTL: 1 * time.Second,
	}

	authService := NewAuthService(mockRepo, config, mockTx)

	user := &models.User{
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
			Return(nil, ErrUserNotFound)

		_, err := authService.GetUser(context.Background(), "not-exist")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrUserNotFound))
	})

	t.Run("empty user ID", func(t *testing.T) {
		mockRepo.EXPECT().
			GetUserByID(gomock.Any(), "").
			Return(nil, ErrFailedToGetUser)

		_, err := authService.GetUser(context.Background(), "")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrFailedToGetUser))
	})

	t.Run("invalid user ID format", func(t *testing.T) {
		mockRepo.EXPECT().
			GetUserByID(gomock.Any(), "invalid-id-format").
			Return(nil, ErrFailedToGetUser)

		_, err := authService.GetUser(context.Background(), "invalid-id-format")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrFailedToGetUser))
	})
}

func TestAuthService_UpdateUser(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockUserRepository(ctrl)
	mockTx := mocks.NewMockTxManagerInterface(ctrl)
	config := jwt.Config{
		Secret:   "secret",
		TokenTTL: 1 * time.Second,
	}

	authService := NewAuthService(mockRepo, config, mockTx)

	user := &models.User{
		ID:       "111",
		Username: "test",
		Email:    "test@test.com",
		Role:     "user",
	}

	t.Run("success", func(t *testing.T) {
		mockTx.EXPECT().
			RunSerializable(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, f func(context.Context) error) error {
				mockRepo.EXPECT().GetUserByID(gomock.Any(), "111").Return(user, nil)
				mockRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(nil)
				return f(ctx)
			})

		resp, err := authService.UpdateUser(context.Background(),
			user.ID,
			"new-username",
			"new-country",
			int32(20),
		)
		assert.NoError(t, err)
		assert.Equal(t, "new-username", resp.Username)
	})

	t.Run("user not found", func(t *testing.T) {
		mockTx.EXPECT().
			RunSerializable(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, f func(context.Context) error) error {
				mockRepo.EXPECT().
					GetUserByID(gomock.Any(), "not-exist").
					Return(nil, ErrFailedToGetUser)
				return f(ctx)
			})

		_, err := authService.UpdateUser(context.Background(),
			"not-exist",
			"new-username",
			"new-country",
			int32(20),
		)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrFailedToGetUser))
	})

}
