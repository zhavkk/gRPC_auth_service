// Package service реализует бизнес-логику сервиса авторизации.
package service

import "errors"

var (
	ErrUserNotFound               = errors.New("user not found")
	ErrInvalidEmail               = errors.New("invalid email")
	ErrInvalidPassword            = errors.New("invalid password")
	ErrInvalidEmailOrPassword     = errors.New("invalid email or password")
	ErrInvalidRole                = errors.New("invalid role")
	ErrInvalidToken               = errors.New("invalid token")
	ErrInvalidUser                = errors.New("invalid user")
	ErrHashPassword               = errors.New("failed to hash password")
	ErrUserAlreadyExists          = errors.New("user with this email already exists")
	ErrFailedToUpdateUser         = errors.New("failed to update user")
	ErrFailedToUpdateRole         = errors.New("failed to update role")
	ErrFailedToUpdatePassword     = errors.New("failed to update password")
	ErrFailedToGetUser            = errors.New("failed to get user")
	ErrFailedToGenerateToken      = errors.New("failed to generate token")
	ErrFailedToCreateUser         = errors.New("failed to create user")
	ErrTokenNotFound              = errors.New("token not found")
	ErrFailedToStoreToken         = errors.New("failed to store token")
	ErrFailedToGetRefreshTokenJTI = errors.New("failed to get refresh token JTI")
	ErrInvalidRefreshToken        = errors.New("invalid refresh token")
	ErrFailedToDeleteRefreshToken = errors.New("failed to delete refresh token")
)
