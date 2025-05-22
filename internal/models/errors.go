// Package models содержит базовые ошибки и доменные сущности для auth-сервиса.
package models

import "errors"

var (
	ErrProfileNotFound = errors.New("profile not found")
	ErrUserNotFound    = errors.New("user not found")
	ErrArtistNotFound  = errors.New("artist not found")
)
