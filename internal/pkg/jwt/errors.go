package jwt

import "errors"

var (
	ErrInvalidRefreshToken        = errors.New("invalid refresh token")
	ErrFailedToGetUser            = errors.New("failed to get user")
	ErrFailedToGenerateToken      = errors.New("failed to generate token")
	ErrFailedToStoreToken         = errors.New("failed to store token")
	ErrFailedToDeleteRefreshToken = errors.New("failed to delete refresh token")
	ErrTokenExpired               = errors.New("token expired")
	ErrInvalidToken               = errors.New("invalid token")
	ErrUnexpectedSigningMethod    = errors.New("unexpected signing method")
)
