package validation

import (
	"regexp"
	"strings"
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
		return ErrPasswordTooShort
	}
	if !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		return ErrPasswordMissingUppercase
	}
	if !regexp.MustCompile(`[a-z]`).MatchString(password) {
		return ErrPasswordMissingLowercase
	}
	if !regexp.MustCompile(`[0-9]`).MatchString(password) {
		return ErrPasswordMissingDigit
	}
	if !regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(password) {
		return ErrPasswordMissingSpecial
	}
	return nil
}

func ValidateAge(age int32) error {
	if age <= 0 || age > 150 {
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
