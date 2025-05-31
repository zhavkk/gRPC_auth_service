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

	"github.com/zhavkk/gRPC_auth_service/internal/config"
	"github.com/zhavkk/gRPC_auth_service/internal/dto"
	"github.com/zhavkk/gRPC_auth_service/internal/kafka/producer"
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

type ProfileRepository interface {
	CreateProfile(ctx context.Context, p *models.Profile) error
	GetProfileByID(ctx context.Context, id string) (*models.Profile, error)
	GetProfileByUsername(ctx context.Context, username string) (*models.Profile, error)
	UpdatePassword(ctx context.Context, id string, newPass string) error
	UpdateRole(ctx context.Context, id string, newRole string) error
	UpdateUsername(ctx context.Context, id string, newUsername string) error
}

type OutboxRepository interface {
	InsertEventTx(ctx context.Context, topic string, key string, payload []byte) error
	FetchUnsentBatch(ctx context.Context, limit int) ([]*models.OutboxEvent, error)
	MarkEventAsSent(ctx context.Context, eventID int64) error
}

type UserRepository interface {
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByID(ctx context.Context, id string) (*models.UserFull, error)
	GetUserByEmail(ctx context.Context, email string) (*models.UserFull, error)
	UpdateUser(ctx context.Context, user *models.User) error
}

type ArtistRepository interface {
	CreateArtist(ctx context.Context, artist *models.Artist) error
	GetArtistByID(ctx context.Context, id string) (*models.ArtistFull, error)
	GetArtistByAuthor(ctx context.Context, author string) (*models.ArtistFull, error)
	UpdateArtist(ctx context.Context, artist *models.Artist) error
}

type AuthService struct {
	userRepo         UserRepository
	profileRepo      ProfileRepository
	artistRepo       ArtistRepository
	jwtConfig        jwt.Config
	txManager        storage.TxManagerInterface
	refreshTokenRepo RefreshTokenRepository
	outboxRepo       OutboxRepository
	kafkaTopics      config.KafkaTopics
}

func NewAuthService(
	userRepo UserRepository,
	profileRepo ProfileRepository,
	artistRepo ArtistRepository,
	jwtConfig jwt.Config,
	txManager storage.TxManagerInterface,
	refreshTokenRepo RefreshTokenRepository,
	outboxRepo OutboxRepository,
	kafkaTopics config.KafkaTopics,
) *AuthService {
	return &AuthService{
		userRepo:         userRepo,
		profileRepo:      profileRepo,
		artistRepo:       artistRepo,
		jwtConfig:        jwtConfig,
		txManager:        txManager,
		refreshTokenRepo: refreshTokenRepo,
		outboxRepo:       outboxRepo,
		kafkaTopics:      kafkaTopics,
	}
}

func (s *AuthService) RegisterUser(
	ctx context.Context,
	params dto.RegisterUserParams,
) (*dto.RegisterUserResponse, error) {
	const op = "auth_service.RegisterUser"

	var resp *dto.RegisterUserResponse

	err := s.txManager.RunSerializable(ctx, func(ctx context.Context) error {
		existingUser, err := s.userRepo.GetUserByEmail(ctx, params.Email)
		if err != nil {
			if !errors.Is(err, models.ErrUserNotFound) {
				return fmt.Errorf("%s: %w", op, err)
			}
		} else if existingUser != nil {
			return fmt.Errorf("%s: %w", op, ErrUserAlreadyExists)
		}

		existingProfile, err := s.profileRepo.GetProfileByUsername(ctx, params.Username)
		if err != nil {
			if !errors.Is(err, models.ErrProfileNotFound) {
				return fmt.Errorf("%s: %w", op, err)
			}
		} else if existingProfile != nil {
			return fmt.Errorf("%s: %w", op, ErrUsernameAlreadyTaken)
		}

		logger.Log.Info(op, "identity passed", params.Username)
		passHash, err := bcrypt.GenerateFromPassword([]byte(params.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("%s: %w", op, ErrHashPassword)
		}

		profileID, err := uuid.NewRandom()
		if err != nil {
			return fmt.Errorf("%s: %w", op, ErrFailedToGenerateProfileID)
		}
		profile := &models.Profile{
			ID:       profileID,
			Username: params.Username,
			PassHash: string(passHash),
			Role:     string(models.RoleUser),
		}
		if err := s.profileRepo.CreateProfile(ctx, profile); err != nil {
			return fmt.Errorf("%s: %w", op, ErrFailedToCreateProfile)
		}
		user := &models.User{
			ProfileID: profile.ID,
			Email:     params.Email,
			Gender:    params.Gender,
			Country:   params.Country,
			Age:       params.Age,
		}
		if err := s.userRepo.CreateUser(ctx, user); err != nil {
			return fmt.Errorf("%s: %w", op, ErrFailedToCreateUser)
		}
		userFull := &models.UserFull{
			ID:        profile.ID,
			Username:  profile.Username,
			Email:     user.Email,
			Gender:    user.Gender,
			Country:   user.Country,
			Age:       user.Age,
			Role:      profile.Role,
			CreatedAt: profile.CreatedAt,
			UpdatedAt: profile.UpdatedAt,
		}
		topic, key, payload, err := producer.BuildUserCreatedMessage(
			userFull, s.kafkaTopics,
		)
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		if err := s.outboxRepo.InsertEventTx(ctx, topic, key, payload); err != nil {
			return fmt.Errorf("%s: %w", op, ErrFailedToInsertEvent)
		}
		resp = &dto.RegisterUserResponse{
			ID: profileID.String(),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	logger.Log.Info(op, "profile_id ", resp.ID)
	return resp, nil
}

func (s *AuthService) RegisterArtist(
	ctx context.Context,
	params dto.RegisterArtistParams,
) (*dto.RegisterArtistResponse, error) {
	const op = "auth_service.RegisterArtist"
	var resp *dto.RegisterArtistResponse
	err := s.txManager.RunSerializable(ctx, func(ctx context.Context) error {
		if _, err := s.artistRepo.GetArtistByAuthor(ctx, params.Author); err != nil {
			if !errors.Is(err, models.ErrArtistNotFound) {
				return fmt.Errorf("%s: %w", op, err)
			}
		} else {
			return fmt.Errorf("%s: %w", op, ErrArtistAlreadyExists)
		}

		if _, err := s.profileRepo.GetProfileByUsername(ctx, params.Username); err != nil {
			if !errors.Is(err, models.ErrProfileNotFound) {
				return fmt.Errorf("%s: %w", op, err)
			}
		} else {
			return fmt.Errorf("%s: %w", op, ErrUsernameAlreadyTaken)
		}
		logger.Log.Info(op, "identity passed", params.Author)
		passHash, err := bcrypt.GenerateFromPassword([]byte(params.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("%s: %w", op, ErrHashPassword)
		}

		profileID, err := uuid.NewRandom()
		if err != nil {
			return fmt.Errorf("%s: %w", op, ErrFailedToGenerateProfileID)
		}
		profile := &models.Profile{
			ID:       profileID,
			Username: params.Username,
			PassHash: string(passHash),
			Role:     string(models.RoleArtist),
		}
		if err := s.profileRepo.CreateProfile(ctx, profile); err != nil {
			return fmt.Errorf("%s: %w", op, ErrFailedToCreateProfile)
		}
		artist := &models.Artist{
			ProfileID:   profile.ID,
			Author:      params.Author,
			Producer:    params.Producer,
			Description: params.Description,
			Country:     params.Country,
		}
		if err := s.artistRepo.CreateArtist(ctx, artist); err != nil {
			return fmt.Errorf("%s: %w", op, ErrFailedToCreateArtist)
		}
		artistFull := &models.ArtistFull{
			ID:          profile.ID,
			Username:    profile.Username,
			Role:        profile.Role,
			CreatedAt:   profile.CreatedAt,
			UpdatedAt:   profile.UpdatedAt,
			Producer:    artist.Producer,
			Author:      artist.Author,
			Country:     artist.Country,
			Description: artist.Description,
		}
		topic, key, payload, err := producer.BuildArtistCreatedMessage(
			artistFull, s.kafkaTopics,
		)
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		if err := s.outboxRepo.InsertEventTx(ctx, topic, key, payload); err != nil {
			return fmt.Errorf("%s: %w", op, ErrFailedToInsertEvent)
		}
		resp = &dto.RegisterArtistResponse{
			ID: profileID.String(),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	logger.Log.Info(op, "profile_id ", resp.ID)
	return resp, nil
}

func (s *AuthService) Login(
	ctx context.Context,
	params dto.LoginParams,
) (*dto.LoginResponse, error) {
	const op = "auth_service.Login"

	profile, err := s.profileRepo.GetProfileByUsername(ctx, params.Username)
	if err != nil {
		logger.Log.Debug("failed to get profile by username",
			slog.String("op", op),
			slog.String("username", params.Username),
			"err", err,
		)
		if errors.Is(err, models.ErrProfileNotFound) {
			return nil, fmt.Errorf("%s: %w", op, ErrInvalidUsernameOrPassword)
		}
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGetProfile)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(profile.PassHash), []byte(params.Password)); err != nil {
		logger.Log.Warn("invalid password attempt",
			slog.String("op", op),
			slog.String("username", params.Username),
			"err", err,
		)
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidUsernameOrPassword)
	}

	accessToken, err := jwt.NewAccessToken(*profile, s.jwtConfig)
	if err != nil {
		logger.Log.Error("failed to generate access token",
			slog.String("op", op),
			slog.String("profile_id", profile.ID.String()),
			"err", err,
		)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGenerateToken)
	}

	refreshTokenJTI, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGenerateToken)
	}
	refreshToken, err := jwt.NewRefreshToken(profile.ID.String(), refreshTokenJTI.String(), s.jwtConfig)
	if err != nil {
		logger.Log.Error("failed to generate refresh token",
			slog.String("op", op),
			slog.String("profile_id", profile.ID.String()),
			"err", err,
		)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGenerateToken)
	}

	err = s.refreshTokenRepo.StoreRefreshToken(ctx,
		profile.ID.String(),
		refreshTokenJTI.String(),
		s.jwtConfig.RefreshTokenTTL,
	)
	if err != nil {
		logger.Log.Error("failed to store refresh token in Redis",
			slog.String("op", op),
			slog.String("profile_id", profile.ID.String()),
			"err", err,
		)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToStoreToken)
	}

	logger.Log.Info("user logged in successfully",
		slog.String("op", op),
		slog.String("user_id",
			profile.ID.String()))
	return &dto.LoginResponse{
		ID:           profile.ID.String(),
		Username:     profile.Username,
		Role:         models.Role(profile.Role),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *AuthService) GetUser(
	ctx context.Context,
	params dto.GetUserParams,
) (*dto.GetUserResponse, error) {
	const op = "auth_service.GetUser"

	var resp *dto.GetUserResponse
	user, err := s.userRepo.GetUserByID(ctx, params.ID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			logger.Log.Error("User not found", "err", err)
			return nil, fmt.Errorf("%s %w", op, ErrUserNotFound)
		}
		logger.Log.Error(op, "err", err)
		return nil, fmt.Errorf("%s %w", op, ErrFailedToGetUser)
	}

	logger.Log.Info(op, "user found successfully", params.ID)
	resp = &dto.GetUserResponse{
		ID:        params.ID,
		Username:  user.Username,
		Email:     user.Email,
		Gender:    user.Gender,
		Country:   user.Country,
		Age:       user.Age,
		Role:      models.Role(user.Role),
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	return resp, nil
}
func (s *AuthService) GetArtist(
	ctx context.Context,
	params dto.GetArtistParams,
) (*dto.GetArtistResponse, error) {
	const op = "auth_service.GetArtist"

	var resp *dto.GetArtistResponse
	artist, err := s.artistRepo.GetArtistByID(ctx, params.ID)
	if err != nil {
		if errors.Is(err, ErrArtistNotFound) {
			logger.Log.Error(op, "err", err)
			return nil, fmt.Errorf("%s %w", op, ErrArtistNotFound)
		}
		logger.Log.Error(op, "err", err)
		return nil, fmt.Errorf("%s %w", op, ErrFailedToGetArtist)
	}

	logger.Log.Info(op, "artist found successfully", params.ID)
	resp = &dto.GetArtistResponse{
		ID:        params.ID,
		Username:  artist.Username,
		Author:    artist.Author,
		Producer:  artist.Producer,
		Country:   artist.Country,
		CreatedAt: artist.CreatedAt,
		UpdatedAt: artist.UpdatedAt,
	}

	return resp, nil
}
func (s *AuthService) UpdateUser(
	ctx context.Context,
	params dto.UpdateUserParams,
) (*dto.UpdateUserResponse, error) {
	const op = "auth_service.UpdateUser"

	var resp *dto.UpdateUserResponse
	err := s.txManager.RunSerializable(ctx, func(ctx context.Context) error {
		userFull, err := s.userRepo.GetUserByID(ctx, params.ID)
		if err != nil {
			return fmt.Errorf("%s: %w", op, ErrFailedToGetUser)
		}

		if other, err := s.profileRepo.GetProfileByUsername(ctx, params.Username); err == nil {
			if other.ID.String() != params.ID {
				return fmt.Errorf("%s: %w", op, ErrUsernameAlreadyTaken)
			}
		} else if !errors.Is(err, models.ErrProfileNotFound) {
			return fmt.Errorf("%s: %w", op, err)
		}

		userFull.Username = params.Username
		userFull.Country = params.Country
		userFull.Age = params.Age

		if err := s.profileRepo.UpdateUsername(ctx, params.ID, params.Username); err != nil {
			return fmt.Errorf("%s: %w", op, ErrFailedToUpdateProfile)
		}
		toUpdate := &models.User{
			ProfileID: userFull.ID,
			Email:     userFull.Email,
			Gender:    userFull.Gender,
			Country:   userFull.Country,
			Age:       userFull.Age,
		}
		if err := s.userRepo.UpdateUser(ctx, toUpdate); err != nil {
			return fmt.Errorf("%s: %w", op, ErrFailedToUpdateUser)
		}

		resp = &dto.UpdateUserResponse{Success: true}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *AuthService) UpdateArtist(
	ctx context.Context,
	params dto.UpdateArtistParams,
) (*dto.UpdateArtistResponse, error) {
	const op = "auth_service.UpdateArtist"

	resp := &dto.UpdateArtistResponse{}

	err := s.txManager.RunSerializable(ctx, func(ctx context.Context) error {
		artistFull, err := s.artistRepo.GetArtistByID(ctx, params.ID)
		if err != nil {
			if errors.Is(err, models.ErrArtistNotFound) {
				return fmt.Errorf("%s: %w", op, ErrArtistNotFound)
			}
			return fmt.Errorf("%s: %w", op, ErrFailedToGetArtist)
		}

		art := &models.Artist{
			ProfileID:   artistFull.ID,
			Author:      params.Author,
			Producer:    params.Producer,
			Country:     params.Country,
			Description: params.Description,
		}

		if err := s.artistRepo.UpdateArtist(ctx, art); err != nil {
			return fmt.Errorf("%s: %w", op, ErrFailedToUpdateArtist)
		}
		resp.Success = true
		return nil
	})

	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (s *AuthService) ChangePassword(
	ctx context.Context,
	params dto.ChangePasswordParams,
) (*dto.ChangePasswordResponse, error) {
	const op = "auth_service.ChangePassword"

	var resp *dto.ChangePasswordResponse
	err := s.txManager.RunSerializable(ctx, func(ctx context.Context) error {
		profile, err := s.profileRepo.GetProfileByID(ctx, params.ID)
		if err != nil {
			logger.Log.Error("Failed to get profile", "err", err)
			return fmt.Errorf("%s %w", op, ErrFailedToGetProfile)
		}

		if err := bcrypt.CompareHashAndPassword([]byte(profile.PassHash), []byte(params.OldPassword)); err != nil {
			return fmt.Errorf("%s %w", op, ErrInvalidPassword)
		}

		PassHash, err := bcrypt.GenerateFromPassword([]byte(params.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			logger.Log.Error(op, "err", err)
			return fmt.Errorf("%s %w", op, ErrHashPassword)
		}

		if err := s.profileRepo.UpdatePassword(ctx, params.ID, string(PassHash)); err != nil {
			logger.Log.Error(op, "err", err)
			return fmt.Errorf("%s %w", op, ErrFailedToUpdatePassword)
		}
		resp = &dto.ChangePasswordResponse{
			Success: true,
		}
		logger.Log.Info(op, "Pass was changed", resp.Success)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%s %w", op, err)
	}
	return resp, nil
}

func (s *AuthService) RefreshToken(
	ctx context.Context,
	params dto.RefreshTokenParams,
) (*dto.RefreshTokenResponse, error) {
	const op = "auth_service.RefreshToken"
	var resp *dto.RefreshTokenResponse
	profileID, jtiFromToken, err := jwt.ParseAndValidateRefreshToken(params.RefreshToken, s.jwtConfig)
	if err != nil {
		logger.Log.Warn("Invalid refresh token received for refresh", "op", op, "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidRefreshToken)
	}

	jtiFromRedis, err := s.refreshTokenRepo.GetRefreshTokenJTI(ctx, profileID)
	if err != nil {
		if errors.Is(err, goRedis.Nil) {
			logger.Log.Warn("Refresh token JTI not found in Redis (token revoked or expired)",
				slog.String("op", op), slog.String("profile_id", profileID))
			return nil, fmt.Errorf("%s: %w", op, ErrTokenNotFound)
		}
		logger.Log.Error("Failed to get refresh token JTI from Redis", "op", op, "profile_id", profileID, "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGetRefreshTokenJTI)
	}

	if jtiFromRedis != jtiFromToken {
		logger.Log.Warn("JTI mismatch for refresh token (potential replay attack or old token)",
			slog.String("op", op), slog.String("profile_id", profileID))
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidRefreshToken)
	}

	err = s.refreshTokenRepo.DeleteRefreshToken(ctx, profileID)
	if err != nil {
		logger.Log.Error("Failed to delete old refresh token JTI from Redis during refresh",
			slog.String("op", op), slog.String("profile_id", profileID), "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToDeleteRefreshToken)
	}

	profile, err := s.profileRepo.GetProfileByID(ctx, profileID)
	if err != nil {
		logger.Log.Error("Failed to get profile for new token generation during refresh",
			slog.String("op", op), slog.String("profile_id", profileID), "err", err)
		if errors.Is(err, models.ErrProfileNotFound) {
			return nil, fmt.Errorf("%s: %w", op, ErrProfileNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGetProfile)
	}

	newAccessToken, err := jwt.NewAccessToken(*profile, s.jwtConfig)
	if err != nil {
		logger.Log.Error(op, "profile_id", profile.ID.String(), "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGenerateToken)
	}

	newJTI, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGenerateToken)
	}

	newRefreshToken, err := jwt.NewRefreshToken(profile.ID.String(), newJTI.String(), s.jwtConfig)
	if err != nil {
		logger.Log.Error("Failed to generate new refresh token during refresh",
			slog.String("op", op), slog.String("profile_id", profile.ID.String()), "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGenerateToken)
	}

	err = s.refreshTokenRepo.StoreRefreshToken(ctx, profile.ID.String(), newJTI.String(), s.jwtConfig.RefreshTokenTTL)
	if err != nil {
		logger.Log.Error("Failed to store new refresh token JTI in Redis during refresh",
			slog.String("op", op), slog.String("profile_id", profile.ID.String()), "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToStoreToken)
	}

	logger.Log.Info(op, "profile_id", profileID)

	resp = &dto.RefreshTokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}
	return resp, nil
}

func (s *AuthService) Logout(
	ctx context.Context,
	params dto.LogoutParams,
) (*dto.LogoutResponse, error) {
	const op = "auth_service.Logout"
	var resp *dto.LogoutResponse
	profileID, _, err := jwt.ParseAndValidateRefreshToken(params.RefreshToken, s.jwtConfig)
	if err != nil {
		logger.Log.Warn("Invalid refresh token received for logout", "op", op, "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrInvalidRefreshToken)
	}

	err = s.refreshTokenRepo.DeleteRefreshToken(ctx, profileID)
	if err != nil {
		logger.Log.Error("Failed to delete refresh token from Redis", "op", op, "user_id", profileID, "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToDeleteRefreshToken)
	}

	resp = &dto.LogoutResponse{
		Success: true,
	}

	return resp, nil
}
