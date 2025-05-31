package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"

	"github.com/zhavkk/gRPC_auth_service/internal/config"
	"github.com/zhavkk/gRPC_auth_service/internal/dto"
	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/models"
	"github.com/zhavkk/gRPC_auth_service/internal/pkg/jwt"
	"github.com/zhavkk/gRPC_auth_service/internal/repository/mocks"
)

func TestAuthService_RegisterUser(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockProfileRepo := mocks.NewMockProfileRepository(ctrl)
	mockArtistRepo := mocks.NewMockArtistRepository(ctrl)
	mockTx := mocks.NewMockTxManagerInterface(ctrl)
	mockRTRepo := mocks.NewMockRefreshTokenRepository(ctrl)
	mockOutboxRepo := mocks.NewMockOutboxRepository(ctrl)
	cfg := jwt.Config{Secret: "secret", AccessTokenTTL: time.Hour, RefreshTokenTTL: 24 * time.Hour}
	kafkaTopics := config.KafkaTopics{
		UserCreatedTopic:   "user.registered",
		ArtistCreatedTopic: "artist.created",
	}
	svc := NewAuthService(
		mockUserRepo,
		mockProfileRepo,
		mockArtistRepo,
		cfg,
		mockTx,
		mockRTRepo,
		mockOutboxRepo,
		kafkaTopics,
	)

	ctx := context.Background()
	params := dto.RegisterUserParams{
		Username: "alice",
		Email:    "alice@example.com",
		Password: "Password123!",
		Gender:   true,
		Country:  "US",
		Age:      30,
	}

	mockTx.EXPECT().
		RunSerializable(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, f func(context.Context) error) error {
			return f(ctx)
		})
	mockUserRepo.EXPECT().
		GetUserByEmail(ctx, params.Email).
		Return(nil, models.ErrUserNotFound)
	mockProfileRepo.EXPECT().
		GetProfileByUsername(ctx, params.Username).
		Return(nil, models.ErrProfileNotFound)
	mockProfileRepo.EXPECT().
		CreateProfile(ctx, gomock.Any()).
		Return(nil)
	mockUserRepo.EXPECT().
		CreateUser(ctx, gomock.Any()).
		Return(nil)
	mockOutboxRepo.EXPECT().
		InsertEventTx(gomock.Any(), "user.registered", gomock.Any(), gomock.Any()).
		Return(nil)

	resp, err := svc.RegisterUser(ctx, params)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp.ID)

	mockTx.EXPECT().
		RunSerializable(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, f func(context.Context) error) error {
			return f(ctx)
		})
	mockUserRepo.EXPECT().
		GetUserByEmail(ctx, params.Email).
		Return(nil, models.ErrUserNotFound)
	mockProfileRepo.EXPECT().
		GetProfileByUsername(ctx, params.Username).
		Return(&models.Profile{}, nil)

	_, err = svc.RegisterUser(ctx, params)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrUsernameAlreadyTaken))
}

func TestAuthService_Login(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockProfileRepo := mocks.NewMockProfileRepository(ctrl)
	mockArtistRepo := mocks.NewMockArtistRepository(ctrl)
	mockTx := mocks.NewMockTxManagerInterface(ctrl)
	mockRTRepo := mocks.NewMockRefreshTokenRepository(ctrl)
	mockOutboxRepo := mocks.NewMockOutboxRepository(ctrl)
	cfg := jwt.Config{Secret: "secret", AccessTokenTTL: time.Hour, RefreshTokenTTL: 24 * time.Hour}
	kafkaTopics := config.KafkaTopics{
		UserCreatedTopic:   "user.registered",
		ArtistCreatedTopic: "artist.created",
	}
	svc := NewAuthService(
		mockUserRepo,
		mockProfileRepo,
		mockArtistRepo,
		cfg,
		mockTx,
		mockRTRepo,
		mockOutboxRepo,
		kafkaTopics,
	)
	ctx := context.Background()
	password := "secret"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	profile := &models.Profile{
		ID:       uuid.New(),
		Username: "bob",
		PassHash: string(hash),
		Role:     string(models.RoleUser),
	}

	mockProfileRepo.EXPECT().
		GetProfileByUsername(ctx, "bob").
		Return(profile, nil)
	mockRTRepo.EXPECT().
		StoreRefreshToken(ctx, profile.ID.String(), gomock.Any(), cfg.RefreshTokenTTL).
		Return(nil)

	out, err := svc.Login(ctx, dto.LoginParams{Username: "bob", Password: password})
	assert.NoError(t, err)
	assert.Equal(t, profile.ID.String(), out.ID)
	assert.NotEmpty(t, out.AccessToken)
	assert.NotEmpty(t, out.RefreshToken)

	mockProfileRepo.EXPECT().
		GetProfileByUsername(ctx, "bob").
		Return(profile, nil)

	_, err = svc.Login(ctx, dto.LoginParams{Username: "bob", Password: "wrong"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidUsernameOrPassword))
}

func TestAuthService_ChangePassword(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockTx := mocks.NewMockTxManagerInterface(ctrl)
	mockRTRepo := mocks.NewMockRefreshTokenRepository(ctrl)
	mockProfileRepo := mocks.NewMockProfileRepository(ctrl)
	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockArtistRepo := mocks.NewMockArtistRepository(ctrl)
	mockOutboxRepo := mocks.NewMockOutboxRepository(ctrl)
	cfg := jwt.Config{Secret: "secret", AccessTokenTTL: time.Hour, RefreshTokenTTL: 24 * time.Hour}
	kafkaTopics := config.KafkaTopics{
		UserCreatedTopic:   "user.registered",
		ArtistCreatedTopic: "artist.created",
	}
	svc := NewAuthService(
		mockUserRepo,
		mockProfileRepo,
		mockArtistRepo,
		cfg,
		mockTx,
		mockRTRepo,
		mockOutboxRepo,
		kafkaTopics,
	)
	ctx := context.Background()
	oldPass := "old-pass"
	hash, _ := bcrypt.GenerateFromPassword([]byte(oldPass), bcrypt.DefaultCost)
	profile := &models.Profile{ID: uuid.New(), PassHash: string(hash), Role: models.RoleUser.String()}

	mockTx.EXPECT().
		RunSerializable(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, f func(context.Context) error) error {
			mockProfileRepo.EXPECT().
				GetProfileByID(ctx, profile.ID.String()).
				Return(&models.Profile{ID: profile.ID, PassHash: profile.PassHash, Role: profile.Role}, nil)
			mockProfileRepo.EXPECT().
				UpdatePassword(ctx, profile.ID.String(), gomock.Any()).
				Return(nil)

			return f(ctx)
		})

	out, err := svc.ChangePassword(ctx, dto.ChangePasswordParams{
		ID:          profile.ID.String(),
		OldPassword: oldPass,
		NewPassword: "new-pass123",
	})
	assert.NoError(t, err)
	assert.True(t, out.Success)
}

func TestAuthService_GetUser(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTx := mocks.NewMockTxManagerInterface(ctrl)
	mockRTRepo := mocks.NewMockRefreshTokenRepository(ctrl)

	mockOutboxRepo := mocks.NewMockOutboxRepository(ctrl)
	cfg := jwt.Config{Secret: "secret", AccessTokenTTL: time.Hour, RefreshTokenTTL: 24 * time.Hour}
	kafkaTopics := config.KafkaTopics{
		UserCreatedTopic:   "user.registered",
		ArtistCreatedTopic: "artist.created",
	}
	svc := NewAuthService(
		mockUserRepo,
		nil,
		nil,
		cfg,
		mockTx,
		mockRTRepo,
		mockOutboxRepo,
		kafkaTopics,
	)
	ctx := context.Background()
	userFull := &models.UserFull{
		ID:       uuid.New(),
		Username: "charlie",
		Email:    "c@e.com",
		Gender:   true,
		Country:  "FR",
		Age:      28,
		Role:     string(models.RoleUser),
	}

	mockUserRepo.EXPECT().
		GetUserByID(ctx, userFull.ID.String()).
		Return(userFull, nil)

	out, err := svc.GetUser(ctx, dto.GetUserParams{ID: userFull.ID.String()})
	assert.NoError(t, err)
	assert.Equal(t, userFull.ID.String(), out.ID)
	assert.Equal(t, userFull.Username, out.Username)

	mockUserRepo.EXPECT().
		GetUserByID(ctx, "nope").
		Return(nil, ErrUserNotFound)

	_, err = svc.GetUser(ctx, dto.GetUserParams{ID: "nope"})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrUserNotFound))
}

func TestAuthService_UpdateUser(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTx := mocks.NewMockTxManagerInterface(ctrl)
	mockRTRepo := mocks.NewMockRefreshTokenRepository(ctrl)
	mockProfileRepo := mocks.NewMockProfileRepository(ctrl)
	mockOutboxRepo := mocks.NewMockOutboxRepository(ctrl)
	cfg := jwt.Config{Secret: "secret", AccessTokenTTL: time.Hour, RefreshTokenTTL: 24 * time.Hour}
	kafkaTopics := config.KafkaTopics{
		UserCreatedTopic:   "user.registered",
		ArtistCreatedTopic: "artist.created",
	}
	svc := NewAuthService(
		mockUserRepo,
		mockProfileRepo,
		nil,
		cfg,
		mockTx,
		mockRTRepo,
		mockOutboxRepo,
		kafkaTopics,
	)
	ctx := context.Background()
	existing := &models.UserFull{ID: uuid.New(), Username: "dave"}

	mockTx.EXPECT().
		RunSerializable(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, f func(context.Context) error) error {
			mockUserRepo.EXPECT().
				GetUserByID(ctx, existing.ID.String()).
				Return(existing, nil)
			mockProfileRepo.EXPECT().
				GetProfileByUsername(ctx, "dave2").
				Return(nil, models.ErrProfileNotFound)
			mockProfileRepo.EXPECT().
				UpdateUsername(ctx, existing.ID.String(), "dave2").
				Return(nil)
			mockUserRepo.EXPECT().
				UpdateUser(ctx, gomock.Any()).
				Return(nil)
			return f(ctx)
		})

	out, err := svc.UpdateUser(ctx, dto.UpdateUserParams{
		ID:       existing.ID.String(),
		Username: "dave2",
		Country:  "DE",
		Age:      35,
	})
	assert.NoError(t, err)
	assert.True(t, out.Success)

	mockTx.EXPECT().
		RunSerializable(gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, f func(context.Context) error) error {
			mockUserRepo.EXPECT().
				GetUserByID(ctx, "nope").
				Return(nil, ErrFailedToGetUser)
			return f(ctx)
		})

	_, err = svc.UpdateUser(ctx, dto.UpdateUserParams{
		ID:       "nope",
		Username: "x",
	})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFailedToGetUser))
}

func TestAuthService_RefreshToken(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockUserRepository(ctrl)
	mockTx := mocks.NewMockTxManagerInterface(ctrl)
	mockRTRepo := mocks.NewMockRefreshTokenRepository(ctrl)
	mockProfileRepo := mocks.NewMockProfileRepository(ctrl)
	mockArtistRepo := mocks.NewMockArtistRepository(ctrl)

	mockOutboxRepo := mocks.NewMockOutboxRepository(ctrl)
	cfg := jwt.Config{Secret: "secret", AccessTokenTTL: time.Hour, RefreshTokenTTL: 24 * time.Hour}
	kafkaTopics := config.KafkaTopics{
		UserCreatedTopic:   "user.registered",
		ArtistCreatedTopic: "artist.created",
	}
	svc := NewAuthService(
		mockUserRepo,
		mockProfileRepo,
		mockArtistRepo,
		cfg,
		mockTx,
		mockRTRepo,
		mockOutboxRepo,
		kafkaTopics,
	)
	ctx := context.Background()
	userID := uuid.New().String()
	oldJTI := "jti-old"
	token, _ := jwt.NewRefreshToken(userID, oldJTI, cfg)

	profile := &models.Profile{
		ID:       uuid.MustParse(userID),
		Username: "testuser",
		Role:     string(models.RoleUser),
	}

	mockRTRepo.EXPECT().GetRefreshTokenJTI(ctx, userID).Return(oldJTI, nil)
	mockRTRepo.EXPECT().DeleteRefreshToken(ctx, userID).Return(nil)
	mockProfileRepo.EXPECT().GetProfileByID(ctx, userID).Return(profile, nil)
	mockRTRepo.EXPECT().StoreRefreshToken(ctx, userID, gomock.Any(), cfg.RefreshTokenTTL).Return(nil)

	out, err := svc.RefreshToken(ctx, dto.RefreshTokenParams{RefreshToken: token})
	assert.NoError(t, err)
	assert.NotEmpty(t, out.AccessToken)
	assert.NotEmpty(t, out.RefreshToken)
}

func TestAuthService_Logout(t *testing.T) {
	logger.Log = slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRTRepo := mocks.NewMockRefreshTokenRepository(ctrl)
	mockOutboxRepo := mocks.NewMockOutboxRepository(ctrl)
	cfg := jwt.Config{Secret: "secret", AccessTokenTTL: time.Hour, RefreshTokenTTL: 24 * time.Hour}
	kafkaTopics := config.KafkaTopics{
		UserCreatedTopic:   "user.registered",
		ArtistCreatedTopic: "artist.created",
	}
	svc := NewAuthService(
		nil,
		nil,
		nil,
		cfg,
		nil,
		mockRTRepo,
		mockOutboxRepo,
		kafkaTopics,
	)
	ctx := context.Background()
	userID := uuid.New().String()
	jti := "jti-x"
	token, _ := jwt.NewRefreshToken(userID, jti, cfg)

	mockRTRepo.EXPECT().
		DeleteRefreshToken(ctx, userID).
		Return(nil)

	out, err := svc.Logout(ctx, dto.LogoutParams{RefreshToken: token})
	assert.NoError(t, err)
	assert.True(t, out.Success)
}
