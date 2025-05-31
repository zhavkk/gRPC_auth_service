package postgres

import "errors"

var (
	ErrFailedToCreateUser     = errors.New("failed to create user")
	ErrFailedToGetUser        = errors.New("failed to get user")
	ErrFailedToGetProfile     = errors.New("failed to get profile")
	ErrFailedToGetArtist      = errors.New("failed to get artist")
	ErrFailedToUpdateUser     = errors.New("failed to update user")
	ErrFailedToUpdatePassword = errors.New("failed to update password")
	ErrFailedToUpdateRole     = errors.New("failed to update role")
	ErrFailedToCreateProfile  = errors.New("failed to create profile")
	ErrFailedToCreateArtist   = errors.New("failed to create artist")
	ErrFailedToUpdateArtist   = errors.New("failed to update artist")
	ErrFailedToUpdateProfile  = errors.New("failed to update profile")
	ErrNoTransactionInContext = errors.New("no transaction in context")
)
