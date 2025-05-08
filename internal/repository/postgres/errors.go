package postgres

import "errors"

var (
	ErrFailedToCreateUser     = errors.New("failed to create user")
	ErrFailedToGetUser        = errors.New("failed to get user")
	ErrFailedToUpdateUser     = errors.New("failed to update user")
	ErrFailedToUpdatePassword = errors.New("failed to update password")
	ErrFailedToUpdateRole     = errors.New("failed to update role")
)
