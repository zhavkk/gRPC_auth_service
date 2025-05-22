package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/models"
	"github.com/zhavkk/gRPC_auth_service/internal/storage"
)

type ArtistRepositoryPostgres struct {
	storage *storage.Storage
}

func NewArtistRepository(storage *storage.Storage,
) *ArtistRepositoryPostgres {
	return &ArtistRepositoryPostgres{
		storage: storage,
	}
}

func (r *ArtistRepositoryPostgres) CreateArtist(
	ctx context.Context,
	artist *models.Artist,
) error {
	const op = "artist_repository.CreateArtist"
	logger.Log.Debug(op, "profile_id", artist.ProfileID)

	query := `
	INSERT INTO artists (
		profile_id, author, producer, country, description
	) VALUES ($1, $2, $3, $4, $5)
	`
	if tx, ok := storage.GetTxFromContext(ctx); ok {
		if _, err := tx.Exec(ctx, query,
			artist.ProfileID,
			artist.Author,
			artist.Producer,
			artist.Country,
			artist.Description,
		); err != nil {
			logger.Log.Error(op, "err", err)
			return fmt.Errorf("%s: %w", op, ErrFailedToCreateArtist)
		}
		return nil
	}
	if _, err := r.storage.GetPool().Exec(ctx, query,
		artist.ProfileID,
		artist.Author,
		artist.Producer,
		artist.Country,
		artist.Description,
	); err != nil {
		logger.Log.Error(op, "err", err)
		return fmt.Errorf("%s: %w", op, ErrFailedToCreateArtist)
	}
	logger.Log.Info(op, "profile_id", artist.ProfileID)
	return nil
}

func (r *ArtistRepositoryPostgres) GetArtistByID(
	ctx context.Context,
	id string,
) (*models.ArtistFull, error) {
	const op = "artist_repository.GetArtistByID"
	logger.Log.Debug(op, "profile_id", id)
	query := `
	SELECT
		p.id, p.username, p.role, p.created_at, p.updated_at,
		a.author, a.producer, a.country, a.description
	FROM profiles p
	JOIN artists a ON a.profile_id = p.id
	WHERE p.id = $1
	`

	var af models.ArtistFull
	var err error
	if tx, ok := storage.GetTxFromContext(ctx); ok {
		err = tx.QueryRow(ctx, query, id).Scan(
			&af.ID,
			&af.Username,
			&af.Role,
			&af.CreatedAt,
			&af.UpdatedAt,
			&af.Author,
			&af.Producer,
			&af.Country,
			&af.Description,
		)
	} else {
		err = r.storage.GetPool().QueryRow(ctx, query, id).Scan(
			&af.ID,
			&af.Username,
			&af.Role,
			&af.CreatedAt,
			&af.UpdatedAt,
			&af.Author,
			&af.Producer,
			&af.Country,
			&af.Description,
		)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, models.ErrArtistNotFound)
		}
		logger.Log.Error(op, "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGetArtist)
	}
	logger.Log.Info(op, "profile_id", af.ID)
	return &af, nil
}

func (r *ArtistRepositoryPostgres) GetArtistByAuthor(
	ctx context.Context,
	author string,
) (*models.ArtistFull, error) {
	const op = "artist_repository.GetArtistByAuthor"
	logger.Log.Debug(op, "author", author)

	query := `
	SELECT
		p.id, p.username, p.role, p.created_at, p.updated_at,
		a.author, a.producer, a.country, a.description
	FROM profiles p
	JOIN artists a ON a.profile_id = p.id
	WHERE a.author = $1
	`
	var af models.ArtistFull
	var err error
	if tx, ok := storage.GetTxFromContext(ctx); ok {
		err = tx.QueryRow(ctx, query, author).Scan(
			&af.ID,
			&af.Username,
			&af.Role,
			&af.CreatedAt,
			&af.UpdatedAt,
			&af.Author,
			&af.Producer,
			&af.Country,
			&af.Description,
		)
	} else {
		err = r.storage.GetPool().QueryRow(ctx, query, author).Scan(
			&af.ID,
			&af.Username,
			&af.Role,
			&af.CreatedAt,
			&af.UpdatedAt,
			&af.Author,
			&af.Producer,
			&af.Country,
			&af.Description,
		)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, models.ErrArtistNotFound)
		}
		logger.Log.Error(op, "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGetArtist)
	}
	logger.Log.Info(op, "author", af.Author)
	return &af, nil
}

func (r *ArtistRepositoryPostgres) UpdateArtist(
	ctx context.Context,
	artist *models.Artist,
) error {
	const op = "artist_repository.UpdateArtist"
	logger.Log.Debug(op, "prodile_id", artist.ProfileID)

	query := `
	UPDATE artists SET
		author = $1,
		producer = $2,
		country = $3,
		description = $4,
		updated_at = now()
	WHERE profile_id = $5
	`
	if tx, ok := storage.GetTxFromContext(ctx); ok {
		if _, err := tx.Exec(ctx, query,
			artist.Author,
			artist.Producer,
			artist.Country,
			artist.Description,
			artist.ProfileID,
		); err != nil {
			logger.Log.Error(op, "err", err)
			return fmt.Errorf("%s: %w", op, ErrFailedToUpdateArtist)
		}
		return nil
	}
	if _, err := r.storage.GetPool().Exec(ctx, query,
		artist.Author,
		artist.Producer,
		artist.Country,
		artist.Description,
		artist.ProfileID,
	); err != nil {
		logger.Log.Error(op, "err", err)
		return fmt.Errorf("%s: %w", op, ErrFailedToUpdateArtist)
	}
	logger.Log.Info(op, "profile_id", artist.ProfileID)
	return nil
}
