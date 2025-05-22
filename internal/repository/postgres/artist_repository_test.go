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

func setupArtistTestDB(t *testing.T) *pgxpool.Pool {
	dsn := "postgres://testuser:testpass@localhost:5432/auth_db?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	db, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)

	_, err = db.Exec(ctx, "TRUNCATE artists, profiles RESTART IDENTITY CASCADE;")
	require.NoError(t, err)

	return db
}

func TestArtistRepository_Postgres(t *testing.T) {
	logger.Log = slog.Default()
	db := setupArtistTestDB(t)
	defer db.Close()

	cfg := config.Config{DBURL: "postgres://testuser:testpass@localhost:5432/auth_db?sslmode=disable"}
	store, err := storage.NewStorage(context.Background(), &cfg)
	require.NoError(t, err)

	repo := NewArtistRepository(store)
	ctx := context.Background()

	t.Run("CreateArtist", func(t *testing.T) {
		profileID := uuid.New()
		existing := &models.Profile{
			ID:       profileID,
			Username: "artist_user",
			PassHash: "pass",
			Role:     "artist",
		}
		_, err = db.Exec(ctx, `
			INSERT INTO profiles (id, username, pass_hash, role, created_at, updated_at)
			VALUES ($1, $2, $3, $4, now(), now())
		`, existing.ID, existing.Username, existing.PassHash, existing.Role)
		require.NoError(t, err)

		art := &models.Artist{
			ProfileID:   profileID,
			Author:      "TheBand",
			Producer:    "Prod",
			Country:     "US",
			Description: "Desc",
		}
		err := repo.CreateArtist(ctx, art)
		require.NoError(t, err)

		var count int
		err = db.QueryRow(ctx,
			"SELECT count(*) FROM artists WHERE profile_id = $1 AND author = $2",
			profileID, art.Author).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count)
	})

	profileID := uuid.New()
	existing := &models.Profile{
		ID:       profileID,
		Username: "artist_user2",
		PassHash: "pass",
		Role:     "artist",
	}
	_, err = db.Exec(ctx, `
		INSERT INTO profiles (id, username, pass_hash, role, created_at, updated_at)
		VALUES ($1, $2, $3, $4, now(), now())
	`, existing.ID, existing.Username, existing.PassHash, existing.Role)
	require.NoError(t, err)

	author := "Solo"
	_, err = db.Exec(ctx, `
		INSERT INTO artists (profile_id, author, producer, country, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, now(), now())
	`, profileID, author, "P", "UK", "Desc")
	require.NoError(t, err)

	t.Run("GetArtistByID success", func(t *testing.T) {
		af, err := repo.GetArtistByID(ctx, profileID.String())
		require.NoError(t, err)
		assert.Equal(t, profileID, af.ID)
		assert.Equal(t, existing.Username, af.Username)
		assert.Equal(t, existing.Role, af.Role)
		assert.Equal(t, author, af.Author)
	})

	t.Run("GetArtistByID not found", func(t *testing.T) {
		_, err := repo.GetArtistByID(ctx, uuid.New().String())
		require.Error(t, err)
		assert.ErrorIs(t, err, models.ErrArtistNotFound)
	})

	t.Run("GetArtistByAuthor success", func(t *testing.T) {
		af, err := repo.GetArtistByAuthor(ctx, author)
		require.NoError(t, err)
		assert.Equal(t, profileID, af.ID)
		assert.Equal(t, author, af.Author)
	})

	t.Run("GetArtistByAuthor not found", func(t *testing.T) {
		_, err := repo.GetArtistByAuthor(ctx, "Unknown")
		require.Error(t, err)
		assert.ErrorIs(t, err, models.ErrArtistNotFound)
	})

	t.Run("UpdateArtist success", func(t *testing.T) {
		upd := &models.Artist{
			ProfileID:   profileID,
			Author:      "UpdatedSolo",
			Producer:    "NewProd",
			Country:     "CA",
			Description: "NewDesc",
		}
		require.NoError(t, repo.UpdateArtist(ctx, upd))

		var got models.ArtistFull
		err := db.QueryRow(ctx,
			`SELECT p.id, p.username, p.role, a.author, a.producer, a.country, a.description
			FROM profiles p JOIN artists a on a.profile_id = p.id WHERE p.id=$1`,
			profileID).Scan(
			&got.ID, &got.Username, &got.Role,
			&got.Author, &got.Producer, &got.Country, &got.Description,
		)
		require.NoError(t, err)
		assert.Equal(t, upd.Author, got.Author)
		assert.Equal(t, upd.Producer, got.Producer)
		assert.Equal(t, upd.Country, got.Country)
		assert.Equal(t, upd.Description, got.Description)
	})
}
