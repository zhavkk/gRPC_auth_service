package postgres

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zhavkk/gRPC_auth_service/internal/config"
	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/models"
	"github.com/zhavkk/gRPC_auth_service/internal/storage"
)

func setupTestDB(t *testing.T) *pgxpool.Pool {
	dsn := "postgres://testuser:testpass@localhost:5432/auth_db?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err, "failed to connect to test db")

	_, err = db.Exec(ctx, "TRUNCATE users, profiles RESTART IDENTITY CASCADE;")
	require.NoError(t, err, "failed to truncate tables")

	return db
}

func TestUserRepository_Postgres(t *testing.T) {
	logger.Log = slog.Default()
	db := setupTestDB(t)
	defer db.Close()

	cfg := config.Config{
		DBURL: "postgres://testuser:testpass@localhost:5432/auth_db?sslmode=disable",
	}
	store, err := storage.NewStorage(context.Background(), &cfg)
	require.NoError(t, err, "failed to create storage")

	repo := NewUserRepository(store)

	ctx := context.Background()

	profileID := uuid.New()
	userProfile := &models.Profile{
		ID:       profileID,
		Username: "testuser",
		PassHash: "hash",
		Role:     "user",
	}
	_, err = db.Exec(ctx, `
		INSERT INTO profiles (id, username, pass_hash, role, created_at, updated_at)
		VALUES ($1, $2, $3, $4, now(), now())
	`, userProfile.ID, userProfile.Username, userProfile.PassHash, userProfile.Role)
	require.NoError(t, err, "failed to insert profile")

	user := &models.User{
		ProfileID: profileID,
		Email:     "test@example.com",
		Gender:    true,
		Country:   "RU",
		Age:       25,
	}
	_, err = db.Exec(ctx, `
		INSERT INTO users (profile_id, email, gender, country, age, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, now(), now())
	`, user.ProfileID, user.Email, user.Gender, user.Country, user.Age)
	require.NoError(t, err, "failed to insert user details")

	t.Run("CreateUser", func(t *testing.T) {
		newProfile := &models.Profile{
			ID:       uuid.New(),
			Username: "create_user",
			PassHash: "h",
			Role:     "user",
		}
		_, err := db.Exec(ctx, `
			INSERT INTO profiles (id, username, pass_hash, role, created_at, updated_at)
			VALUES ($1, $2, $3, $4, now(), now())
		`, newProfile.ID, newProfile.Username, newProfile.PassHash, newProfile.Role)
		require.NoError(t, err)

		newUser := &models.User{
			ProfileID: newProfile.ID,
			Email:     "new@example.com",
			Gender:    false,
			Country:   "US",
			Age:       30,
		}
		require.NoError(t, repo.CreateUser(ctx, newUser))

		got, err := repo.GetUserByID(ctx, newProfile.ID.String())
		require.NoError(t, err)
		assert.Equal(t, newProfile.ID, got.ID)
		assert.Equal(t, newProfile.Username, got.Username)
		assert.Equal(t, newUser.Email, got.Email)
		assert.Equal(t, newUser.Gender, got.Gender)
		assert.Equal(t, newUser.Country, got.Country)
		assert.Equal(t, newUser.Age, got.Age)
		assert.Equal(t, newProfile.Role, got.Role)
	})

	t.Run("GetUserByEmail - success", func(t *testing.T) {
		got, err := repo.GetUserByEmail(ctx, user.Email)
		require.NoError(t, err)
		assert.Equal(t, userProfile.ID, got.ID)
		assert.Equal(t, userProfile.Username, got.Username)
		assert.Equal(t, user.Email, got.Email)
		assert.Equal(t, user.Gender, got.Gender)
		assert.Equal(t, user.Country, got.Country)
		assert.Equal(t, user.Age, got.Age)
		assert.Equal(t, userProfile.Role, got.Role)
	})

	t.Run("GetUserByEmail - not found", func(t *testing.T) {
		_, err := repo.GetUserByEmail(ctx, "absent@example.com")
		assert.Error(t, err)
	})

	t.Run("GetUserByID - success", func(t *testing.T) {
		got, err := repo.GetUserByID(ctx, userProfile.ID.String())
		require.NoError(t, err)
		assert.Equal(t, userProfile.ID, got.ID)
		assert.Equal(t, userProfile.Username, got.Username)
		assert.Equal(t, user.Email, got.Email)
		assert.Equal(t, user.Gender, got.Gender)
		assert.Equal(t, user.Country, got.Country)
		assert.Equal(t, user.Age, got.Age)
		assert.Equal(t, userProfile.Role, got.Role)
	})

	t.Run("GetUserByID - not found", func(t *testing.T) {
		_, err := repo.GetUserByID(ctx, uuid.New().String())
		assert.Error(t, err)
	})

	t.Run("UpdateUser - success", func(t *testing.T) {
		update := &models.User{
			ProfileID: userProfile.ID,
			Email:     user.Email,
			Gender:    user.Gender,
			Country:   "DE",
			Age:       28,
		}
		require.NoError(t, repo.UpdateUser(ctx, update))

		got, err := repo.GetUserByID(ctx, userProfile.ID.String())
		require.NoError(t, err)
		assert.Equal(t, "DE", got.Country)
		assert.Equal(t, int32(28), got.Age)
		assert.Equal(t, userProfile.ID, got.ID)
		assert.Equal(t, userProfile.Username, got.Username)
		assert.Equal(t, user.Email, got.Email)
		assert.Equal(t, user.Gender, got.Gender)
		assert.Equal(t, userProfile.Role, got.Role)
	})
}
