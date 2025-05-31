// internal/postgres/profile_repository_test.go
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

func setupProfileTestDB(t *testing.T) *pgxpool.Pool {
	dsn := "postgres://testuser:testpass@localhost:5432/auth_db?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	db, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	_, err = db.Exec(ctx, "TRUNCATE profiles RESTART IDENTITY CASCADE;")
	require.NoError(t, err)

	return db
}

func TestProfileRepository_Postgres(t *testing.T) {
	logger.Log = slog.Default()
	db := setupProfileTestDB(t)
	defer db.Close()

	cfg := config.Config{DBURL: "postgres://testuser:testpass@localhost:5432/auth_db?sslmode=disable"}
	store, err := storage.NewStorage(context.Background(), &cfg)
	require.NoError(t, err)

	repo := NewProfileRepository(store)
	ctx := context.Background()

	t.Run("CreateProfile", func(t *testing.T) {
		id := uuid.New()
		p := &models.Profile{
			ID:       id,
			Username: "alice",
			PassHash: "secret",
			Role:     "user",
		}
		err := repo.CreateProfile(ctx, p)
		require.NoError(t, err)

		var count int
		err = db.QueryRow(ctx, "SELECT COUNT(*) FROM profiles WHERE id = $1", id).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count)
	})

	baseID := uuid.New()
	_, err = db.Exec(ctx, `
        INSERT INTO profiles (id, username, pass_hash, role, created_at, updated_at)
        VALUES ($1, $2, $3, $4, now(), now())
    `, baseID, "bob", "hash", "artist")
	require.NoError(t, err)

	t.Run("GetProfileByID success", func(t *testing.T) {
		p, err := repo.GetProfileByID(ctx, baseID.String())
		require.NoError(t, err)
		assert.Equal(t, baseID, p.ID)
		assert.Equal(t, "bob", p.Username)
		assert.Equal(t, "hash", p.PassHash)
		assert.Equal(t, "artist", p.Role)
		assert.False(t, p.CreatedAt.IsZero())
		assert.False(t, p.UpdatedAt.IsZero())
	})

	t.Run("GetProfileByID not found", func(t *testing.T) {
		_, err := repo.GetProfileByID(ctx, uuid.New().String())
		require.Error(t, err)
		assert.ErrorIs(t, err, models.ErrProfileNotFound)
	})

	t.Run("GetProfileByUsername success", func(t *testing.T) {
		p, err := repo.GetProfileByUsername(ctx, "bob")
		require.NoError(t, err)
		assert.Equal(t, baseID, p.ID)
		assert.Equal(t, "bob", p.Username)
	})

	t.Run("GetProfileByUsername not found", func(t *testing.T) {
		_, err := repo.GetProfileByUsername(ctx, "charlie")
		require.Error(t, err)
		assert.ErrorIs(t, err, models.ErrProfileNotFound)
	})

	t.Run("UpdatePassword success", func(t *testing.T) {
		newPass := "newhash"
		err := repo.UpdatePassword(ctx, baseID.String(), newPass)
		require.NoError(t, err)

		var got string
		err = db.QueryRow(ctx, "SELECT pass_hash FROM profiles WHERE id=$1", baseID).Scan(&got)
		require.NoError(t, err)
		assert.Equal(t, newPass, got)
	})

	t.Run("UpdateRole success", func(t *testing.T) {
		newRole := "admin"
		err := repo.UpdateRole(ctx, baseID.String(), newRole)
		require.NoError(t, err)

		var got string
		err = db.QueryRow(ctx, "SELECT role FROM profiles WHERE id=$1", baseID).Scan(&got)
		require.NoError(t, err)
		assert.Equal(t, newRole, got)
	})

	t.Run("UpdateUsername success", func(t *testing.T) {
		newUsername := "bob_renamed"
		err := repo.UpdateUsername(ctx, baseID.String(), newUsername)
		require.NoError(t, err)

		var got string
		err = db.QueryRow(ctx, "SELECT username FROM profiles WHERE id=$1", baseID).Scan(&got)
		require.NoError(t, err)
		assert.Equal(t, newUsername, got)
	})
}
