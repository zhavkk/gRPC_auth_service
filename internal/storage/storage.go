package storage

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zhavkk/gRPC_auth_service/internal/config"
)

type Storage struct {
	db *pgxpool.Pool
}

func NewStorage(ctx context.Context, cfg *config.Config) (*Storage, error) {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		cfg.DB.Host,
		cfg.DB.User,
		cfg.DB.Password,
		cfg.DB.Name,
		cfg.DB.Port,
	)

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to db: %w", err)
	}

	return &Storage{db: pool}, nil
}

func (s *Storage) Close() error {

	if s.db == nil {
		return fmt.Errorf("db is not connected")
	}

	s.db.Close()
	return nil
}

func (s *Storage) GetPool() *pgxpool.Pool {
	return s.db
}
