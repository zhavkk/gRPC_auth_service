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

type UserRepository interface {
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
	UpdateUserRole(ctx context.Context, id string, role string) error
	UpdateUserPassword(ctx context.Context, id string, hashedPassword string) error
}

type UserRepositiryPostgres struct {
	storage *storage.Storage
}

func NewUserRepository(storage *storage.Storage,
) *UserRepositiryPostgres {
	return &UserRepositiryPostgres{
		storage: storage,
	}
}

func (r *UserRepositiryPostgres) CreateUser(ctx context.Context,
	user *models.User,
) error {
	logger.Log.Debug("Creating user... ", "user", user)
	query := `
	INSERT INTO users (id, username, email, pass_hash, gender, country, age, role)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	if tx, ok := storage.GetTxFromContext(ctx); ok {
		_, err := tx.Exec(ctx, query,
			user.ID,
			user.Username,
			user.Email,
			user.PassHash,
			user.Gender,
			user.Country,
			user.Age,
			user.Role,
		)
		if err != nil {
			logger.Log.Error("Failed to create user", "err", err)
			return fmt.Errorf("%s %w", "user_repository.CreateUser", ErrFailedToCreateUser)
		}
		return nil
	}

	_, err := r.storage.GetPool().Exec(ctx, query,
		user.ID,
		user.Username,
		user.Email,
		user.PassHash,
		user.Gender,
		user.Country,
		user.Age,
		user.Role,
	)
	if err != nil {
		logger.Log.Error("Failed to create user", "err", err)
		return fmt.Errorf("%s %w", "user_repository.CreateUser", ErrFailedToCreateUser)
	}

	return nil
}

func (r *UserRepositiryPostgres) GetUserByID(ctx context.Context,
	id string,
) (*models.User, error) {
	logger.Log.Debug("Getting user by id... ", "id", id)
	query := `
	SELECT id,username,email, pass_hash,gender,country,age,role
	FROM users
	WHERE id = $1
	`
	user := &models.User{}
	if tx, ok := storage.GetTxFromContext(ctx); ok {
		err := tx.QueryRow(ctx, query, id).Scan(
			&user.ID,
			&user.Username,
			&user.Email,
			&user.PassHash,
			&user.Gender,
			&user.Country,
			&user.Age,
			&user.Role,
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				logger.Log.Error("User not found", "err", err)
				return nil, fmt.Errorf("%s %w", "user_repository.GetUserByID", models.ErrUserNotFound)
			}
			logger.Log.Error("Failed to get user: ", "err", err)
			return nil, fmt.Errorf("%s %w", "user_repository.GetUserByID", ErrFailedToGetUser)
		}
	} else {
		err := r.storage.GetPool().QueryRow(ctx, query, id).Scan(
			&user.ID,
			&user.Username,
			&user.Email,
			&user.PassHash,
			&user.Gender,
			&user.Country,
			&user.Age,
			&user.Role,
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				logger.Log.Error("User not found", "err", err)
				return nil, fmt.Errorf("%s %w", "user_repository.GetUserByID", models.ErrUserNotFound)
			}
			logger.Log.Error("Failed to get user: ", "err", err)
			return nil, fmt.Errorf("%s %w", "user_repository.GetUserByID", ErrFailedToGetUser)
		}
	}
	logger.Log.Debug("User found: ", "user", user)
	return user, nil
}

func (r *UserRepositiryPostgres) GetUserByEmail(ctx context.Context,
	email string,
) (*models.User, error) {
	logger.Log.Debug("Getting user by email... ", "email", email)
	query := `
	SELECT id, username, email, pass_hash, gender, country, age, role
	FROM users
	WHERE email = $1
	`

	user := &models.User{}

	if tx, ok := storage.GetTxFromContext(ctx); ok {
		err := tx.QueryRow(ctx, query, email).Scan(
			&user.ID,
			&user.Username,
			&user.Email,
			&user.PassHash,
			&user.Gender,
			&user.Country,
			&user.Age,
			&user.Role,
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				logger.Log.Error("User not found", "err", err)
				return nil, fmt.Errorf("%s %w", "user_repository.GetUserByEmail", models.ErrUserNotFound)
			}
			logger.Log.Error("Failed to get user by email", "err", err)
			return nil, fmt.Errorf("%s %w", "user_repository.GetUserByEmail", ErrFailedToGetUser)
		}
		return user, nil
	}

	err := r.storage.GetPool().QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PassHash,
		&user.Gender,
		&user.Country,
		&user.Age,
		&user.Role,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Log.Error("User not found", "err", err)
			return nil, fmt.Errorf("%s %w", "user_repository.GetUserByEmail", models.ErrUserNotFound)
		}
		logger.Log.Error("Failed to get user by email", "err", err)
		return nil, fmt.Errorf("%s %w", "user_repository.GetUserByEmail", ErrFailedToGetUser)
	}

	logger.Log.Debug("User found", "user", user)
	return user, nil
}

func (r *UserRepositiryPostgres) UpdateUser(ctx context.Context,
	user *models.User,
) error {
	logger.Log.Debug("Updating user", "user", user)
	query := `
	UPDATE users
	SET username = $1, email = $2, gender = $3, country = $4, age = $5
	WHERE id = $6
	`

	if tx, ok := storage.GetTxFromContext(ctx); ok {
		_, err := tx.Exec(ctx, query,
			user.Username,
			user.Email,
			user.Gender,
			user.Country,
			user.Age,
			user.ID,
		)
		if err != nil {
			logger.Log.Error("Failed to update user", "err", err)
			return fmt.Errorf("%s %w", "user_repository.UpdateUser", ErrFailedToUpdateUser)
		}
		logger.Log.Info("User updated", "user_id", user.ID)
		return nil
	}

	_, err := r.storage.GetPool().Exec(ctx, query,
		user.Username,
		user.Email,
		user.Gender,
		user.Country,
		user.Age,
		user.ID,
	)
	if err != nil {
		logger.Log.Error("Failed to update user", "err", err)
		return fmt.Errorf("%s %w", "user_repository.UpdateUser", ErrFailedToUpdateUser)
	}

	logger.Log.Info("User updated", "user_id", user.ID)
	return nil
}

func (r *UserRepositiryPostgres) UpdateUserRole(ctx context.Context,
	id string,
	role string,
) error {
	logger.Log.Debug("Updating user role", "user_id", id, "role", role)
	query := `
	UPDATE users
	SET role = $1
	WHERE id = $2
	`

	if tx, ok := storage.GetTxFromContext(ctx); ok {
		_, err := tx.Exec(ctx, query, role, id)
		if err != nil {
			logger.Log.Error("Failed to update user role", "err", err)
			return fmt.Errorf("%s %w", "user_repository.UpdateUserRole", ErrFailedToUpdateRole)
		}
		logger.Log.Info("User role updated", "user_id", id)
		return nil
	}

	_, err := r.storage.GetPool().Exec(ctx, query, role, id)
	if err != nil {
		logger.Log.Error("Failed to update user role", "err", err)
		return fmt.Errorf("%s %w", "user_repository.UpdateUserRole", ErrFailedToUpdateRole)
	}

	logger.Log.Info("User role updated", "user_id", id)
	return nil
}

func (r *UserRepositiryPostgres) UpdateUserPassword(ctx context.Context,
	id string,
	hashedPassword string,
) error {
	logger.Log.Debug("Updating user password", "user_id", id)
	query := `
	UPDATE users
	SET pass_hash = $1
	WHERE id = $2
	`

	if tx, ok := storage.GetTxFromContext(ctx); ok {
		_, err := tx.Exec(ctx, query, hashedPassword, id)
		if err != nil {
			logger.Log.Error("Failed to update user password", "err", err)
			return fmt.Errorf("%s %w", "user_repository.UpdateUserPassword", ErrFailedToUpdatePassword)
		}
		logger.Log.Info("User password updated", "user_id", id)
		return nil
	}

	_, err := r.storage.GetPool().Exec(ctx, query, hashedPassword, id)
	if err != nil {
		logger.Log.Error("Failed to update user password", "err", err)
		return fmt.Errorf("%s %w", "user_repository.UpdateUserPassword", ErrFailedToUpdatePassword)
	}

	logger.Log.Info("User password updated", "user_id", id)
	return nil
}
