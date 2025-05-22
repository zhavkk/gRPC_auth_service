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

type ProfileRepositoryPostgres struct {
	storage *storage.Storage
}

func NewProfileRepository(storage *storage.Storage,
) *ProfileRepositoryPostgres {
	return &ProfileRepositoryPostgres{
		storage: storage,
	}
}

func (r *ProfileRepositoryPostgres) CreateProfile(
	ctx context.Context,
	profile *models.Profile,
) error {
	const op = "profile_repository.CreateProfile"
	logger.Log.Debug(op, "username", profile.Username)

	query := `
	INSERT INTO profiles (
		id, username,pass_hash,role	
	) VALUES ($1,$2,$3,$4)
	`

	if tx, ok := storage.GetTxFromContext(ctx); ok {
		if _, err := tx.Exec(ctx, query,
			profile.ID,
			profile.Username,
			profile.PassHash,
			profile.Role,
		); err != nil {
			logger.Log.Error(op, "err", err)
			return fmt.Errorf("%s: %w", op, ErrFailedToCreateProfile)
		}
		return nil
	}
	if _, err := r.storage.GetPool().Exec(ctx, query,
		profile.ID,
		profile.Username,
		profile.PassHash,
		profile.Role,
	); err != nil {
		logger.Log.Error(op, "err", err)
		return fmt.Errorf("%s: %w", op, ErrFailedToCreateProfile)
	}
	return nil
}

func (r *ProfileRepositoryPostgres) GetProfileByID(
	ctx context.Context,
	id string,
) (*models.Profile, error) {
	const op = "profile_repository.GetProfileByID"
	logger.Log.Debug(op, "id", id)

	query := `
	SELECT id, username, pass_hash, role, created_at, updated_at
	FROM profiles
	WHERE id = $1
	`

	var p models.Profile
	var err error

	if tx, ok := storage.GetTxFromContext(ctx); ok {
		err = tx.QueryRow(ctx, query, id).Scan(
			&p.ID,
			&p.Username,
			&p.PassHash,
			&p.Role,
			&p.CreatedAt,
			&p.UpdatedAt,
		)
	} else {
		err = r.storage.GetPool().QueryRow(ctx, query, id).Scan(
			&p.ID,
			&p.Username,
			&p.PassHash,
			&p.Role,
			&p.CreatedAt,
			&p.UpdatedAt,
		)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, models.ErrProfileNotFound)
		}
		logger.Log.Error(op, "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGetProfile)
	}
	return &p, nil

}

func (r *ProfileRepositoryPostgres) GetProfileByUsername(ctx context.Context,
	username string,
) (*models.Profile, error) {
	const op = "profile_repository.GetProfileByUsername"
	logger.Log.Debug(op, "username", username)

	const query = `
	SELECT id, username, pass_hash, role, created_at, updated_at
	FROM profiles
	WHERE username = $1
	`
	var p models.Profile
	var err error

	if tx, ok := storage.GetTxFromContext(ctx); ok {
		err = tx.QueryRow(ctx, query, username).Scan(
			&p.ID,
			&p.Username,
			&p.PassHash,
			&p.Role,
			&p.CreatedAt,
			&p.UpdatedAt,
		)
	} else {
		err = r.storage.GetPool().QueryRow(ctx, query, username).Scan(
			&p.ID,
			&p.Username,
			&p.PassHash,
			&p.Role,
			&p.CreatedAt,
			&p.UpdatedAt,
		)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, models.ErrProfileNotFound)
		}
		logger.Log.Error(op, "err", err)
		return nil, fmt.Errorf("%s: %w", op, ErrFailedToGetProfile)
	}
	return &p, nil
}

func (r *ProfileRepositoryPostgres) UpdatePassword(
	ctx context.Context,
	id string,
	newPass string,
) error {
	const op = "profile_repository.UpdatePassword"
	logger.Log.Debug(op, "id", id)

	const query = `
	UPDATE profiles
	SET pass_hash = $1, updated_at = now()
	WHERE id = $2
	`
	if tx, ok := storage.GetTxFromContext(ctx); ok {
		if _, err := tx.Exec(ctx, query, newPass, id); err != nil {
			logger.Log.Error(op, "err", err)
			return fmt.Errorf("%s: %w", op, ErrFailedToUpdatePassword)
		}
		return nil
	}
	if _, err := r.storage.GetPool().Exec(ctx, query, newPass, id); err != nil {
		logger.Log.Error(op, "err", err)
		return fmt.Errorf("%s: %w", op, ErrFailedToUpdatePassword)
	}
	return nil
}

func (r *ProfileRepositoryPostgres) UpdateRole(
	ctx context.Context,
	id string,
	newRole string,
) error {
	const op = "profile_repository.UpdateRole"
	logger.Log.Debug(op, "id", id, "role", newRole)

	const query = `
	UPDATE profiles
	SET role = $1, updated_at = now()
	WHERE id = $2
	`
	if tx, ok := storage.GetTxFromContext(ctx); ok {
		if _, err := tx.Exec(ctx, query, newRole, id); err != nil {
			logger.Log.Error(op, "err", err)
			return fmt.Errorf("%s: %w", op, ErrFailedToUpdateRole)
		}
		return nil
	}
	if _, err := r.storage.GetPool().Exec(ctx, query, newRole, id); err != nil {
		logger.Log.Error(op, "err", err)
		return fmt.Errorf("%s: %w", op, ErrFailedToUpdateRole)
	}
	return nil
}

func (r *ProfileRepositoryPostgres) UpdateUsername(
	ctx context.Context,
	id string,
	newUsername string,
) error {
	const op = "profile_repository.UpdateUsername"
	logger.Log.Debug(op, "profile_id", id, "new_username", newUsername)

	query := `
    UPDATE profiles
    SET username = $1, updated_at = now()
    WHERE id = $2
    `
	if tx, ok := storage.GetTxFromContext(ctx); ok {
		if _, err := tx.Exec(ctx, query, newUsername, id); err != nil {
			logger.Log.Error(op, "err", err)
			return fmt.Errorf("%s: %w", op, ErrFailedToUpdateProfile)
		}
		return nil
	}
	if _, err := r.storage.GetPool().Exec(ctx, query, newUsername, id); err != nil {
		logger.Log.Error(op, "err", err)
		return fmt.Errorf("%s: %w", op, ErrFailedToUpdateProfile)
	}

	return nil
}
