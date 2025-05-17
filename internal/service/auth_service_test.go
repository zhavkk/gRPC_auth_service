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

	goRedis "github.com/redis/go-redis/v9"

	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/models"
	"github.com/zhavkk/gRPC_auth_service/internal/pkg/jwt"
	"github.com/zhavkk/gRPC_auth_service/internal/repository/mocks"
)

func TestAuthService_Register(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTxManager := mocks.NewMockTxManagerInterface(ctrl)
	mockRefreshTokenRepo := mocks.NewMockRefreshTokenRepository(ctrl)

	config := jwt.Config{
		Secret:          "secret",
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
	}
	authService := NewAuthService(mockUserRepo, config, mockTxManager, mockRefreshTokenRepo)

	t.Run("success", func(t *testing.T) {
		mockTxManager.EXPECT().RunSerializable(gomock.Any(),
			gomock.Any(),
		).DoAndReturn(func(ctx context.Context,
			f func(context.Context) error,
		) error {
			return f(ctx)
		})

		mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(), "test@test.com").Return(nil, ErrUserNotFound)
		mockUserRepo.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(nil)

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
		mockTxManager.EXPECT().RunSerializable(gomock.Any(),
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
		mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(),
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
		assert.True(t, errors.Is(err, ErrUserAlreadyExists))
	})
}

func TestAuthService_Login(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTxManager := mocks.NewMockTxManagerInterface(ctrl)
	mockRefreshTokenRepo := mocks.NewMockRefreshTokenRepository(ctrl)

	config := jwt.Config{
		Secret:          "secret",
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
	}
	authService := NewAuthService(mockUserRepo, config, mockTxManager, mockRefreshTokenRepo)

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
		mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(),
			"test@test.com",
		).Return(user, nil)

		mockRefreshTokenRepo.EXPECT().StoreRefreshToken(
			gomock.Any(),
			user.ID,
			gomock.Any(),
			config.RefreshTokenTTL,
		).Return(nil)

		response, err := authService.Login(context.Background(),
			"test@test.com",
			"password123",
		)
		assert.NoError(t, err)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)
		assert.Equal(t, user.ID, response.ID)
		assert.Equal(t, user.Email, response.Email)
		assert.Equal(t, user.Username, response.Username)
		assert.Equal(t, user.Role, response.Role)
	})

	t.Run("user not found", func(t *testing.T) {
		mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(),
			"notfound@test.com",
		).Return(nil, models.ErrUserNotFound)

		_, err := authService.Login(context.Background(),
			"notfound@test.com",
			"password123",
		)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidEmailOrPassword))
	})

	t.Run("wrong password", func(t *testing.T) {
		mockUserRepo.EXPECT().GetUserByEmail(gomock.Any(),
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

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTxManager := mocks.NewMockTxManagerInterface(ctrl)
	mockRefreshTokenRepo := mocks.NewMockRefreshTokenRepository(ctrl)

	config := jwt.Config{
		Secret:          "secret",
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
	}
	authService := NewAuthService(mockUserRepo, config, mockTxManager, mockRefreshTokenRepo)

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
		mockTxManager.EXPECT().RunSerializable(gomock.Any(),
			gomock.Any(),
		).DoAndReturn(func(ctx context.Context,
			f func(context.Context) error,
		) error {
			return f(ctx)
		})

		mockUserRepo.EXPECT().GetUserByID(gomock.Any(),
			"user-id",
		).Return(user, nil)
		mockUserRepo.EXPECT().UpdateUserPassword(gomock.Any(),
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

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTxManager := mocks.NewMockTxManagerInterface(ctrl)
	mockRefreshTokenRepo := mocks.NewMockRefreshTokenRepository(ctrl)

	config := jwt.Config{
		Secret:          "secret",
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
	}
	authService := NewAuthService(mockUserRepo, config, mockTxManager, mockRefreshTokenRepo)

	user := &models.User{
		ID:       "user-id",
		Username: "test",
		Email:    "test@test.com",
		Role:     "user",
	}

	t.Run("success", func(t *testing.T) {
		mockTxManager.EXPECT().RunSerializable(gomock.Any(),
			gomock.Any(),
		).DoAndReturn(func(ctx context.Context,
			f func(context.Context) error,
		) error {
			return f(ctx)
		})

		mockUserRepo.EXPECT().GetUserByID(gomock.Any(), "user-id").Return(user, nil)
		mockUserRepo.EXPECT().UpdateUserRole(gomock.Any(), "user-id", "admin").Return(nil)

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

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTxManager := mocks.NewMockTxManagerInterface(ctrl)
	mockRefreshTokenRepo := mocks.NewMockRefreshTokenRepository(ctrl)

	config := jwt.Config{
		Secret:          "secret",
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
	}

	authService := NewAuthService(mockUserRepo, config, mockTxManager, mockRefreshTokenRepo)

	user := &models.User{
		ID:       "user-id",
		Username: "test",
		Email:    "test@test.com",
		Role:     "user",
	}

	t.Run("success", func(t *testing.T) {
		mockUserRepo.EXPECT().
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
		mockUserRepo.EXPECT().
			GetUserByID(gomock.Any(), "not-exist").
			Return(nil, ErrUserNotFound)

		_, err := authService.GetUser(context.Background(), "not-exist")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrUserNotFound))
	})
}

func TestAuthService_UpdateUser(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTxManager := mocks.NewMockTxManagerInterface(ctrl)
	mockRefreshTokenRepo := mocks.NewMockRefreshTokenRepository(ctrl)

	config := jwt.Config{
		Secret:          "secret",
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
	}

	authService := NewAuthService(mockUserRepo, config, mockTxManager, mockRefreshTokenRepo)

	user := &models.User{
		ID:       "111",
		Username: "test",
		Email:    "test@test.com",
		Role:     "user",
	}

	t.Run("success", func(t *testing.T) {
		mockTxManager.EXPECT().
			RunSerializable(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, f func(context.Context) error) error {
				mockUserRepo.EXPECT().GetUserByID(gomock.Any(), "111").Return(user, nil)
				mockUserRepo.EXPECT().UpdateUser(gomock.Any(), gomock.Any()).Return(nil)
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
		mockTxManager.EXPECT().
			RunSerializable(gomock.Any(), gomock.Any()).
			DoAndReturn(func(ctx context.Context, f func(context.Context) error) error {
				mockUserRepo.EXPECT().
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

func TestAuthService_RefreshToken(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTxManager := mocks.NewMockTxManagerInterface(ctrl)
	mockRefreshTokenRepo := mocks.NewMockRefreshTokenRepository(ctrl)

	config := jwt.Config{
		Secret:          "secret", // Short TTL for expiry test
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
	}
	authService := NewAuthService(mockUserRepo, config, mockTxManager, mockRefreshTokenRepo)

	userID := "test-user-id"
	oldJTI := "old-jti"
	oldRefreshToken, err := jwt.NewRefreshToken(userID, oldJTI, config)
	assert.NoError(t, err)

	user := &models.User{
		ID:       userID,
		Email:    "test@example.com",
		Username: "testuser",
		Role:     "user",
	}

	t.Run("success", func(t *testing.T) {
		mockRefreshTokenRepo.EXPECT().GetRefreshTokenJTI(gomock.Any(), userID).Return(oldJTI, nil)
		mockRefreshTokenRepo.EXPECT().DeleteRefreshToken(gomock.Any(), userID).Return(nil)
		mockUserRepo.EXPECT().GetUserByID(gomock.Any(), userID).Return(user, nil)
		mockRefreshTokenRepo.EXPECT().StoreRefreshToken(
			gomock.Any(), userID, gomock.Any(), config.RefreshTokenTTL,
		).Return(nil)

		response, err := authService.RefreshToken(context.Background(), oldRefreshToken)
		assert.NoError(t, err)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)

		parsedAccessToken, err := jwt.ValidateToken(response.AccessToken, config)
		assert.NoError(t, err)
		assert.Equal(t, userID, parsedAccessToken[jwt.ClaimUUID].(string))

		parsedRefreshTokenUserID, parsedRefreshTokenJTI, err := jwt.ParseAndValidateRefreshToken(
			response.RefreshToken, config,
		)
		assert.NoError(t, err)
		assert.Equal(t, userID, parsedRefreshTokenUserID)
		assert.NotEqual(t, oldJTI, parsedRefreshTokenJTI)
	})

	t.Run("error validating old refresh token - invalid token", func(t *testing.T) {
		_, err := authService.RefreshToken(context.Background(), "invalid-token-string")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidRefreshToken))
	})

	t.Run("error validating old refresh token - expired", func(t *testing.T) {
		expiredConfig := jwt.Config{
			Secret:          "secret",
			AccessTokenTTL:  1 * time.Hour,
			RefreshTokenTTL: -1 * time.Hour,
		}
		expiredToken, _ := jwt.NewRefreshToken(userID, "some-jti", expiredConfig)
		time.Sleep(10 * time.Millisecond)

		_, err := authService.RefreshToken(context.Background(), expiredToken)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidRefreshToken))
	})

	t.Run("jti not found in redis", func(t *testing.T) {
		mockRefreshTokenRepo.EXPECT().GetRefreshTokenJTI(gomock.Any(), userID).Return("", goRedis.Nil)

		_, err := authService.RefreshToken(context.Background(), oldRefreshToken)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrTokenNotFound))
	})

	t.Run("jti mismatch", func(t *testing.T) {
		mockRefreshTokenRepo.EXPECT().GetRefreshTokenJTI(gomock.Any(), userID).Return("different-jti-from-redis", nil)

		_, err := authService.RefreshToken(context.Background(), oldRefreshToken)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidRefreshToken))
	})

	t.Run("error deleting old refresh token", func(t *testing.T) {
		mockRefreshTokenRepo.EXPECT().GetRefreshTokenJTI(gomock.Any(), userID).Return(oldJTI, nil)
		mockRefreshTokenRepo.EXPECT().DeleteRefreshToken(gomock.Any(), userID).Return(errors.New("db error"))

		_, err := authService.RefreshToken(context.Background(), oldRefreshToken)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrFailedToDeleteRefreshToken))
	})

	t.Run("error get user by id", func(t *testing.T) {
		mockRefreshTokenRepo.EXPECT().GetRefreshTokenJTI(gomock.Any(), userID).Return(oldJTI, nil)
		mockRefreshTokenRepo.EXPECT().DeleteRefreshToken(gomock.Any(), userID).Return(nil)
		mockUserRepo.EXPECT().GetUserByID(gomock.Any(), userID).Return(nil, models.ErrUserNotFound)

		_, err := authService.RefreshToken(context.Background(), oldRefreshToken)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrUserNotFound))
	})

	t.Run("error storing new refresh token", func(t *testing.T) {
		mockRefreshTokenRepo.EXPECT().GetRefreshTokenJTI(gomock.Any(), userID).Return(oldJTI, nil)
		mockRefreshTokenRepo.EXPECT().DeleteRefreshToken(gomock.Any(), userID).Return(nil)
		mockUserRepo.EXPECT().GetUserByID(gomock.Any(), userID).Return(user, nil)
		mockRefreshTokenRepo.EXPECT().StoreRefreshToken(
			gomock.Any(), userID, gomock.Any(), config.RefreshTokenTTL,
		).Return(errors.New("db error"))

		_, err := authService.RefreshToken(context.Background(), oldRefreshToken)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrFailedToStoreToken))
	})
}

func TestAuthService_Logout(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTxManager := mocks.NewMockTxManagerInterface(ctrl)
	mockRefreshTokenRepo := mocks.NewMockRefreshTokenRepository(ctrl)

	config := jwt.Config{
		Secret:          "secret",
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
	}
	authService := NewAuthService(mockUserRepo, config, mockTxManager, mockRefreshTokenRepo)

	userID := "test-user-id"
	jti := "some-jti"
	refreshToken, err := jwt.NewRefreshToken(userID, jti, config)
	assert.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		mockRefreshTokenRepo.EXPECT().DeleteRefreshToken(gomock.Any(), userID).Return(nil)

		response, err := authService.Logout(context.Background(), refreshToken)
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.True(t, response.Success)
	})

	t.Run("error validating refresh token - invalid token", func(t *testing.T) {
		_, err := authService.Logout(context.Background(), "invalid-token-string")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidRefreshToken))
	})

	t.Run("error validating refresh token - expired", func(t *testing.T) {
		expiredConfig := jwt.Config{
			Secret:          "secret",
			AccessTokenTTL:  1 * time.Hour,
			RefreshTokenTTL: -1 * time.Hour,
		}
		expiredToken, _ := jwt.NewRefreshToken(userID, "some-jti", expiredConfig)
		time.Sleep(10 * time.Millisecond)

		_, err := authService.Logout(context.Background(), expiredToken)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidRefreshToken))
	})

	t.Run("error deleting refresh token from repo", func(t *testing.T) {
		mockRefreshTokenRepo.EXPECT().DeleteRefreshToken(gomock.Any(), userID).Return(errors.New("db error"))

		_, err := authService.Logout(context.Background(), refreshToken)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrFailedToDeleteRefreshToken))
	})
}
