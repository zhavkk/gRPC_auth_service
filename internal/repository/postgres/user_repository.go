// Package postgres реализует взаимодействие с таблицей пользователей в PostgreSQL.
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

type UserRepositoryPostgres struct {
	storage *storage.Storage
}

func NewUserRepository(storage *storage.Storage,
) *UserRepositoryPostgres {
	return &UserRepositoryPostgres{
		storage: storage,
	}
}

func (r *UserRepositoryPostgres) CreateUser(ctx context.Context,
	user *models.User,
) error {
	const op = "user_repository.CreateUser"
	logger.Log.Debug(op, "user", user)
	query := `
	INSERT INTO users (
		profile_id, email, gender, country, age
	) VALUES ($1, $2, $3, $4, $5)
	`

	params := []interface{}{user.ProfileID,
		user.Email,
		user.Gender,
		user.Country,
		user.Age,
	}
	if tx, ok := storage.GetTxFromContext(ctx); ok {
		if _, err := tx.Exec(ctx, query, params...); err != nil {
			logger.Log.Error(op, "err", err)
			return fmt.Errorf("%s: %w", op, ErrFailedToCreateUser)
		}
		return nil
	}
	if _, err := r.storage.GetPool().Exec(ctx, query, params...); err != nil {
		logger.Log.Error(op, "err", err)
		return fmt.Errorf("%s: %w", op, ErrFailedToCreateUser)
	}
	return nil
}

func (r *UserRepositoryPostgres) GetUserByID(ctx context.Context,
	id string,
) (*models.UserFull, error) {
	const op = "user_repository.GetUserByID"
	logger.Log.Debug(op, "id", id)
	query := `
	SELECT
		p.id, p.username, p.role, p.created_at, p.updated_at,
		u.email, u.gender, u.country, u.age
	FROM profiles p
	JOIN users u ON u.profile_id = p.id
	WHERE p.id = $1
	`
	var UserFull models.UserFull
	var err error
	if tx, ok := storage.GetTxFromContext(ctx); ok {
		err = tx.QueryRow(ctx, query, id).Scan(
			&UserFull.ID,
			&UserFull.Username,
			&UserFull.Role,
			&UserFull.CreatedAt,
			&UserFull.UpdatedAt,
			&UserFull.Email,
			&UserFull.Gender,
			&UserFull.Country,
			&UserFull.Age,
		)
	} else {
		err = r.storage.GetPool().QueryRow(ctx, query, id).Scan(
			&UserFull.ID,
			&UserFull.Username,
			&UserFull.Role,
			&UserFull.CreatedAt,
			&UserFull.UpdatedAt,
			&UserFull.Email,
			&UserFull.Gender,
			&UserFull.Country,
			&UserFull.Age,
		)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%s %w", op, models.ErrUserNotFound)
		}
		logger.Log.Error(op, "err", err)
		return nil, fmt.Errorf("%s %w", op, ErrFailedToGetUser)
	}
	logger.Log.Debug(op, "userFull", UserFull)
	return &UserFull, nil
}

func (r *UserRepositoryPostgres) GetUserByEmail(ctx context.Context,
	email string,
) (*models.UserFull, error) {
	const op = "user_repository.GetUserByEmail"
	logger.Log.Debug(op, "email", email)
	query := `
	SELECT
		p.id, p.username, p.role, p.created_at, p.updated_at,
		u.email, u.gender, u.country, u.age
	FROM profiles p
	JOIN users u ON u.profile_id = p.id
	WHERE u.email = $1
	`

	var UserFull models.UserFull
	var err error
	if tx, ok := storage.GetTxFromContext(ctx); ok {
		err = tx.QueryRow(ctx, query, email).Scan(
			&UserFull.ID,
			&UserFull.Username,
			&UserFull.Role,
			&UserFull.CreatedAt,
			&UserFull.UpdatedAt,
			&UserFull.Email,
			&UserFull.Gender,
			&UserFull.Country,
			&UserFull.Age,
		)
	} else {
		err = r.storage.GetPool().QueryRow(ctx, query, email).Scan(
			&UserFull.ID,
			&UserFull.Username,
			&UserFull.Role,
			&UserFull.CreatedAt,
			&UserFull.UpdatedAt,
			&UserFull.Email,
			&UserFull.Gender,
			&UserFull.Country,
			&UserFull.Age,
		)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Log.Debug(op, "email", email, "err", err)
			return nil, fmt.Errorf("%s %w", op, models.ErrUserNotFound)
		}
		logger.Log.Error(op, "err", err)
		return nil, fmt.Errorf("%s %w", op, ErrFailedToGetUser)
	}

	logger.Log.Debug(op, "userFull", UserFull)
	return &UserFull, nil
}

func (r *UserRepositoryPostgres) UpdateUser(ctx context.Context,
	user *models.User,
) error {
	const op = "user_repository.UpdateUser"
	logger.Log.Debug(op, "user", user)
	query := `
	UPDATE users SET
		email = $1,
		gender = $2,
		country = $3,
		age = $4,
		updated_at = now()
	WHERE profile_id = $5
	`
	if tx, ok := storage.GetTxFromContext(ctx); ok {
		if _, err := tx.Exec(ctx,
			query,
			user.Email,
			user.Gender,
			user.Country,
			user.Age,
			user.ProfileID,
		); err != nil {
			logger.Log.Error(op, "err", err)
			return fmt.Errorf("%s: %w", op, ErrFailedToUpdateUser)
		}
		return nil
	}
	if _, err := r.storage.GetPool().Exec(ctx,
		query,
		user.Email,
		user.Gender,
		user.Country,
		user.Age,
		user.ProfileID,
	); err != nil {
		logger.Log.Error(op, "err", err)
		return fmt.Errorf("%s: %w", op, ErrFailedToUpdateUser)
	}
	return nil
}
