// Package auth реализует gRPC-методы для аутентификации пользователей.
package auth

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zhavkk/gRPC_auth_service/internal/service"
	authproto "github.com/zhavkk/gRPC_auth_service/pkg/authpb"
)

func (s *serverAPI) Login(ctx context.Context,
	req *authproto.LoginRequest,
) (*authproto.LoginResponse, error) {
	if err := s.validator.ValidateLoginRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := s.service.Login(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, service.ErrFailedToGenerateToken) {
			return nil, status.Error(codes.Internal, err.Error())
		}
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	return &authproto.LoginResponse{
		Id:           resp.ID,
		Username:     resp.Username,
		Email:        resp.Email,
		Role:         resp.Role,
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
	}, nil
}

func (s *serverAPI) ChangePassword(ctx context.Context,
	req *authproto.ChangePasswordRequest,
) (*authproto.ChangePasswordResponse, error) {
	if err := s.validator.ValidateChangePasswordRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	userIDFromToken, err := GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if req.Id != userIDFromToken {
		return nil, status.Error(codes.PermissionDenied, "you can only change your own password")
	}
	resp, err := s.service.ChangePassword(ctx, req.GetId(), req.GetOldPassword(), req.GetNewPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	resp.Success = true

	return &authproto.ChangePasswordResponse{
		Success: resp.Success,
	}, nil
}

func (s *serverAPI) RefreshToken(ctx context.Context,
	req *authproto.RefreshTokenRequest,
) (*authproto.RefreshTokenResponse, error) {
	if err := s.validator.ValidateRefreshTokenRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := s.service.RefreshToken(ctx, req.GetRefreshToken())
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) ||
			errors.Is(err, service.ErrInvalidRefreshToken) ||
			errors.Is(err, service.ErrTokenNotFound) {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &authproto.RefreshTokenResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
	}, nil
}

func (s *serverAPI) Logout(ctx context.Context,
	req *authproto.LogoutRequest,
) (*authproto.LogoutResponse, error) {
	if err := s.validator.ValidateLogoutRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	_, err := s.service.Logout(ctx, req.GetRefreshToken())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &authproto.LogoutResponse{
		Success: true,
		Message: "Logout successful",
	}, nil
}
