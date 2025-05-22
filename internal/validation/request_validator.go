// Package validation содержит функции валидации входящих gRPC-запросов.
package validation

import (
	"strings"

	auth "github.com/zhavkk/gRPC_auth_service/pkg/authpb"
)

func ValidateRegisterUserRequest(req *auth.RegisterUserRequest) error {
	if err := ValidateUsername(req.GetUsername()); err != nil {
		return err
	}
	if err := ValidateEmail(req.GetEmail()); err != nil {
		return err
	}
	if err := ValidatePassword(req.GetPassword()); err != nil {
		return err
	}
	return ValidateAge(req.GetAge())
}

func ValidateRegisterArtistRequest(req *auth.RegisterArtistRequest) error {
	if err := ValidateUsername(req.GetUsername()); err != nil {
		return err
	}

	return ValidatePassword(req.GetPassword())
}

func ValidateLoginRequest(req *auth.LoginRequest) error {
	if err := ValidateUsername(req.GetUsername()); err != nil {
		return err
	}
	return ValidatePassword(req.GetPassword())
}

func ValidateGetUserRequest(req *auth.GetUserRequest) error {
	if req.GetId() == "" {
		return ErrUserIDRequired
	}
	return nil
}

func ValidateGetArtistRequest(req *auth.GetArtistRequest) error {
	if req.GetId() == "" {
		return ErrArtistIDRequired
	}
	return nil
}

func ValidateUpdateUserRequest(req *auth.UpdateUserRequest) error {
	if req.GetId() == "" {
		return ErrUserIDRequired
	}
	if req.GetUsername() != "" {
		if err := ValidateUsername(req.GetUsername()); err != nil {
			return err
		}
	}
	if req.GetAge() != 0 {
		return ValidateAge(req.GetAge())
	}
	return nil
}
func ValidateUpdateArtistRequest(req *auth.UpdateArtistRequest) error {
	if req.GetId() == "" {
		return ErrArtistIDRequired
	}
	if req.GetAuthor() != "" {
		if err := ValidateAuthor(req.GetAuthor()); err != nil {
			return err
		}
	}
	return nil
}
func ValidateChangePasswordRequest(req *auth.ChangePasswordRequest) error {
	if req.GetId() == "" {
		return ErrUserIDRequired
	}
	if err := ValidatePassword(req.GetOldPassword()); err != nil {
		return err
	}
	return ValidatePassword(req.GetNewPassword())
}

func ValidateRegistrationRole(role string) error {
	if role == "" {
		return ErrRoleRequired
	}
	validRoles := map[string]bool{
		"user":   true,
		"artist": true,
	}
	if !validRoles[strings.ToLower(role)] {
		return ErrRoleMustBeUserOrArtist
	}
	return nil
}

func ValidateRefreshTokenRequest(req *auth.RefreshTokenRequest) error {
	if req.GetRefreshToken() == "" {
		return ErrRefreshTokenRequired
	}
	return nil
}

func ValidateLogoutRequest(req *auth.LogoutRequest) error {
	if req.GetRefreshToken() == "" {
		return ErrRefreshTokenRequired
	}
	return nil
}
