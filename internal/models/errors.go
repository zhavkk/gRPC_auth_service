// Package models содержит базовые ошибки и доменные сущности для auth-сервиса.
package models

import "errors"

var ErrUserNotFound = errors.New("user not found")
