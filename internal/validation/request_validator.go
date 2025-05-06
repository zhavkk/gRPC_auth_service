package validation

import (
	"errors"
	"strings"

	"github.com/zhavkk/Auth-protobuf/gen/go/auth"
)

func ValidateRegisterRequest(req *auth.RegisterRequest) error {
	if err := ValidateUsername(req.GetUsername()); err != nil {
		return err
	}
	if err := ValidateEmail(req.GetEmail()); err != nil {
		return err
	}
	if err := ValidatePassword(req.GetPassword()); err != nil {
		return err
	}
	if err := ValidateAge(req.GetAge()); err != nil {
		return err
	}
	if err := ValidateRegistrationRole(req.GetRole()); err != nil {
		return err
	}
	return nil
}

func ValidateLoginRequest(req *auth.LoginRequest) error {
	if err := ValidateEmail(req.GetEmail()); err != nil {
		return err
	}
	if err := ValidatePassword(req.GetPassword()); err != nil {
		return err
	}
	return nil
}

func ValidateSetUserRoleRequest(req *auth.SetUserRoleRequest) error {
	if req.GetId() == "" {
		return errors.New("invalid user ID")
	}
	if err := ValidateRole(req.GetRole()); err != nil {
		return err
	}
	return nil
}

func ValidateGetUserRequest(req *auth.GetUserRequest) error {
	if req.GetId() == "" {
		return errors.New("invalid user ID")
	}
	return nil
}

func ValidateUpdateUserRequest(req *auth.UpdateUserRequest) error {
	if req.GetId() == "" {
		return errors.New("invalid user ID")
	}
	if req.GetUsername() != "" {
		if err := ValidateUsername(req.GetUsername()); err != nil {
			return err
		}
	}
	if req.GetAge() != 0 {
		if err := ValidateAge(req.GetAge()); err != nil {
			return err
		}
	}
	return nil
}

func ValidateChangePasswordRequest(req *auth.ChangePasswordRequest) error {
	if req.GetId() == "" {
		return errors.New("invalid user ID")
	}
	if err := ValidatePassword(req.GetOldPassword()); err != nil {
		return err
	}
	if err := ValidatePassword(req.GetNewPassword()); err != nil {
		return err
	}
	return nil
}

// for registration
func ValidateRegistrationRole(role string) error {
	if role == "" {
		return errors.New("role is required")
	}
	validRoles := map[string]bool{
		"user":   true,
		"artist": true,
	}
	if !validRoles[strings.ToLower(role)] {
		return errors.New("role must be either 'user' or 'artist'")
	}
	return nil
}
