package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/zhavkk/gRPC_auth_service/internal/domain"
	"github.com/zhavkk/gRPC_auth_service/internal/storage"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user *domain.User) error
	GetUserByID(ctx context.Context, id string) (*domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	UpdateUser(ctx context.Context, user *domain.User) error
	UpdateUserRole(ctx context.Context, id string, role string) error
	UpdateUserPassword(ctx context.Context, id string, hashedPassword string) error
}

type UserRepositiryPostgres struct {
	storage *storage.Storage
	log     *slog.Logger
}

func NewUserRepository(storage *storage.Storage, log *slog.Logger) *UserRepositiryPostgres {
	return &UserRepositiryPostgres{
		storage: storage,
		log:     log,
	}
}

func (r *UserRepositiryPostgres) CreateUser(ctx context.Context, user *domain.User) error {
	r.log.Debug("Creating user... ", "user", user)
	query := `
	INSERT INTO users (id, username, email, pass_hash, gender, country, age, role)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
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
		r.log.Error("Failed to create user", "error", err)
		return fmt.Errorf("failed to create user: %w", err)
	}

	r.log.Info("User created", "user_id", user.ID)
	return nil
}

func (r *UserRepositiryPostgres) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	r.log.Debug("Getting user by id... ", "id", id)
	query := `
	SELECT id,username,email, pass_hash,gender,country,age,role
	FROM users
	WHERE id = $1
	`

	user := &domain.User{}

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
			return nil, domain.ErrUserNotFound
		}
		r.log.Error("Failed to get user: ", "err", err)
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	r.log.Debug("User found: ", "user", user)
	return user, nil
}

func (r *UserRepositiryPostgres) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	r.log.Debug("Getting user by email... ", "email", email)
	query := `
	SELECT id, username, email, pass_hash, gender, country, age, role
	FROM users
	WHERE email = $1
	`

	user := &domain.User{}

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
			return nil, domain.ErrUserNotFound
		}
		r.log.Error("Failed to get user", "error", err)
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	r.log.Debug("User found", "user", user)
	return user, nil
}

func (r *UserRepositiryPostgres) UpdateUser(ctx context.Context, user *domain.User) error {
	r.log.Debug("Updating user", "user", user)
	query := `
	UPDATE users
	SET username = $1, email = $2, gender = $3, country = $4, age = $5
	WHERE id = $6
	`

	_, err := r.storage.GetPool().Exec(ctx, query,
		user.Username,
		user.Email,
		user.Gender,
		user.Country,
		user.Age,
		user.ID,
	)
	if err != nil {
		r.log.Error("Failed to update user", "error", err)
		return fmt.Errorf("failed to update user: %w", err)
	}

	r.log.Info("User updated", "user_id", user.ID)
	return nil
}

func (r *UserRepositiryPostgres) UpdateUserRole(ctx context.Context, id string, role string) error {
	r.log.Debug("Updating user role", "user_id", id, "role", role)
	query := `
	UPDATE users
	SET role = $1
	WHERE id = $2
	`

	_, err := r.storage.GetPool().Exec(ctx, query, role, id)
	if err != nil {
		r.log.Error("Failed to update user role", "error", err)
		return fmt.Errorf("failed to update user role: %w", err)
	}

	r.log.Info("User role updated", "user_id", id)
	return nil
}

func (r *UserRepositiryPostgres) UpdateUserPassword(ctx context.Context, id string, hashedPassword string) error {
	r.log.Debug("Updating user password", "user_id", id)
	query := `
	UPDATE users
	SET pass_hash = $1
	WHERE id = $2
	`

	_, err := r.storage.GetPool().Exec(ctx, query, hashedPassword, id)
	if err != nil {
		r.log.Error("Failed to update user password", "error", err)
		return fmt.Errorf("failed to update user password: %w", err)
	}

	r.log.Info("User password updated", "user_id", id)
	return nil
}
