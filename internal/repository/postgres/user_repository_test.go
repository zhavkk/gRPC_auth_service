package postgres

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"

	"github.com/zhavkk/gRPC_auth_service/internal/config"
	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/models"
	"github.com/zhavkk/gRPC_auth_service/internal/storage"
)

func setupTestDB(t *testing.T) *pgxpool.Pool {
	dsn := "postgres://testuser:testpass@localhost:5432/testdb?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("failed to connect to test db: %v", err)
	}

	_, err = db.Exec(ctx, "TRUNCATE users RESTART IDENTITY CASCADE;")
	if err != nil {
		t.Fatalf("failed to truncate users: %v", err)
	}

	return db
}

func TestUserRepository_Postgres(t *testing.T) {
	logger.Log = slog.Default()
	db := setupTestDB(t)
	defer db.Close()

	cfg := config.Config{

		DBURL: "postgres://testuser:testpass@localhost:5432/testdb?sslmode=disable",
	}

	storage, err := storage.NewStorage(context.Background(), &cfg)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	repo := NewUserRepository(storage)

	ctx := context.Background()

	user := &models.User{
		ID:       uuid.New().String(),
		Username: "testuser",
		Email:    "test@example.com",
		PassHash: "hash",
		Gender:   true,
		Country:  "RU",
		Age:      25,
		Role:     "user",
	}

	t.Run("CreateUser", func(t *testing.T) {
		err := repo.CreateUser(ctx, user)
		assert.NoError(t, err)
	})

	t.Run("GetUserByEmail - success", func(t *testing.T) {
		got, err := repo.GetUserByEmail(ctx, user.Email)
		assert.NoError(t, err)
		assert.Equal(t, user.Email, got.Email)
		assert.Equal(t, user.Username, got.Username)
	})

	t.Run("GetUserByEmail - not found", func(t *testing.T) {
		_, err := repo.GetUserByEmail(ctx, "notfound@example.com")
		assert.Error(t, err)
	})

	t.Run("GetUserByID - success", func(t *testing.T) {
		got, err := repo.GetUserByID(ctx, user.ID)
		assert.NoError(t, err)
		assert.Equal(t, user.ID, got.ID)
	})

	t.Run("GetUserByID - not found", func(t *testing.T) {
		_, err := repo.GetUserByID(ctx, uuid.New().String())
		assert.Error(t, err)
	})

	t.Run("UpdateUser", func(t *testing.T) {
		user.Username = "updateduser"
		user.Country = "US"
		user.Age = 30
		err := repo.UpdateUser(ctx, user)
		assert.NoError(t, err)

		got, err := repo.GetUserByID(ctx, user.ID)
		assert.NoError(t, err)
		assert.Equal(t, "updateduser", got.Username)
		assert.Equal(t, "US", got.Country)
		assert.Equal(t, int32(30), got.Age)
	})

	t.Run("UpdateUserRole", func(t *testing.T) {
		err := repo.UpdateUserRole(ctx, user.ID, "admin")
		assert.NoError(t, err)

		got, err := repo.GetUserByID(ctx, user.ID)
		assert.NoError(t, err)
		assert.Equal(t, "admin", got.Role)
	})

	t.Run("UpdateUserPassword", func(t *testing.T) {
		newHash := "newhash"
		err := repo.UpdateUserPassword(ctx, user.ID, newHash)
		assert.NoError(t, err)

		got, err := repo.GetUserByID(ctx, user.ID)
		assert.NoError(t, err)
		assert.Equal(t, newHash, got.PassHash)
	})
}
