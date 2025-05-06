package validation

import (
	"errors"
	"regexp"
	"strings"
)

var (
	ErrInvalidUsername = errors.New("username must be between 3 and 20 characters")
	ErrInvalidEmail    = errors.New("invalid email format")
	ErrInvalidPassword = errors.New("password must be at least 8 characters long")
	ErrInvalidAge      = errors.New("age must be between 0 and 150")
	ErrInvalidRole     = errors.New("invalid role")
)

func ValidateUsername(username string) error {
	if len(username) < 3 || len(username) > 20 {
		return ErrInvalidUsername
	}
	return nil
}

func ValidateEmail(email string) error {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return ErrInvalidEmail
	}
	return nil
}

func ValidatePassword(password string) error {
	if len(password) < 8 {
		return ErrInvalidPassword
	}
	if !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !regexp.MustCompile(`[a-z]`).MatchString(password) {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !regexp.MustCompile(`[0-9]`).MatchString(password) {
		return errors.New("password must contain at least one number")
	}
	if !regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(password) {
		return errors.New("password must contain at least one special character")
	}
	return nil
}

func ValidateAge(age int32) error {
	if age < 0 || age > 150 {
		return ErrInvalidAge
	}
	return nil
}

func ValidateRole(role string) error {
	validRoles := map[string]bool{
		"admin":  true,
		"user":   true,
		"artist": true,
	}
	if !validRoles[strings.ToLower(role)] {
		return ErrInvalidRole
	}
	return nil
}
