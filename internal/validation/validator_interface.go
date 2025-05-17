package validation

import (
	auth "github.com/zhavkk/gRPC_auth_service/pkg/authpb"
)

type Validator interface {
	ValidateRegisterRequest(req *auth.RegisterRequest) error
	ValidateLoginRequest(req *auth.LoginRequest) error
	ValidateSetUserRoleRequest(req *auth.SetUserRoleRequest) error
	ValidateGetUserRequest(req *auth.GetUserRequest) error
	ValidateUpdateUserRequest(req *auth.UpdateUserRequest) error
	ValidateChangePasswordRequest(req *auth.ChangePasswordRequest) error
	ValidateRefreshTokenRequest(req *auth.RefreshTokenRequest) error
	ValidateLogoutRequest(req *auth.LogoutRequest) error
}

func NewValidator() Validator {
	return &validator{}
}

type validator struct{}

func (v *validator) ValidateRegisterRequest(req *auth.RegisterRequest) error {
	return ValidateRegisterRequest(req)
}

func (v *validator) ValidateLoginRequest(req *auth.LoginRequest) error {
	return ValidateLoginRequest(req)
}

func (v *validator) ValidateSetUserRoleRequest(req *auth.SetUserRoleRequest) error {
	return ValidateSetUserRoleRequest(req)
}

func (v *validator) ValidateGetUserRequest(req *auth.GetUserRequest) error {
	return ValidateGetUserRequest(req)
}

func (v *validator) ValidateUpdateUserRequest(req *auth.UpdateUserRequest) error {
	return ValidateUpdateUserRequest(req)
}

func (v *validator) ValidateChangePasswordRequest(req *auth.ChangePasswordRequest) error {
	return ValidateChangePasswordRequest(req)
}

func (v *validator) ValidateRefreshTokenRequest(req *auth.RefreshTokenRequest) error {
	return ValidateRefreshTokenRequest(req)
}

func (v *validator) ValidateLogoutRequest(req *auth.LogoutRequest) error {
	return ValidateLogoutRequest(req)
}
