// Package auth реализует gRPC-методы для аутентификации пользователей.
package auth

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zhavkk/gRPC_auth_service/internal/dto"
	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/service"
	authproto "github.com/zhavkk/gRPC_auth_service/pkg/authpb"
)

func (s *serverAPI) Login(
	ctx context.Context,
	req *authproto.LoginRequest,
) (*authproto.LoginResponse, error) {
	const op = "serverAPI.Login"

	if err := s.validator.ValidateLoginRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	params := dto.LoginParams{
		Username: req.GetUsername(),
		Password: req.GetPassword(),
	}
	out, err := s.service.Login(ctx, params)
	if err != nil {
		if errors.Is(err, service.ErrInvalidUsernameOrPassword) {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		if errors.Is(err, service.ErrFailedToGenerateToken) {
			return nil, status.Error(codes.Internal, err.Error())
		}
		logger.Log.Error(op, "err", err)
		return nil, status.Error(codes.Internal, ErrInternal)
	}
	return &authproto.LoginResponse{
		Id:           out.ID,
		Username:     out.Username,
		Role:         toProtoRole(out.Role),
		AccessToken:  out.AccessToken,
		RefreshToken: out.RefreshToken,
	}, nil
}

func (s *serverAPI) ChangePassword(
	ctx context.Context,
	req *authproto.ChangePasswordRequest,
) (*authproto.ChangePasswordResponse, error) {
	const op = "serverAPI.ChangePassword"

	if err := s.validator.ValidateChangePasswordRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	callerID, err := GetUserIDFromContext(ctx)
	if err != nil {
		logger.Log.Warn(op, "err", err)
		return nil, status.Error(codes.Unauthenticated, ErrInvalidToken)
	}

	if req.GetId() != callerID {
		logger.Log.Warn(op,
			"permission denied",
			slog.String("caller_id", callerID),
			slog.String("target_id", req.GetId()),
		)
		return nil, status.Error(codes.PermissionDenied, ErrPermissionDenied)
	}
	params := dto.ChangePasswordParams{
		ID:          req.GetId(),
		OldPassword: req.GetOldPassword(),
		NewPassword: req.GetNewPassword(),
	}

	out, err := s.service.ChangePassword(ctx, params)
	if err != nil {

		if errors.Is(err, service.ErrInvalidPassword) {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		if errors.Is(err, service.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		logger.Log.Error(op, "err", err)
		return nil, status.Error(codes.Internal, ErrInternal)
	}
	return &authproto.ChangePasswordResponse{
		Success: out.Success,
	}, nil
}

func (s *serverAPI) RefreshToken(ctx context.Context,
	req *authproto.RefreshTokenRequest,
) (*authproto.RefreshTokenResponse, error) {
	const op = "serverAPI.RefreshToken"
	if err := s.validator.ValidateRefreshTokenRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	params := dto.RefreshTokenParams{
		RefreshToken: req.GetRefreshToken(),
	}

	resp, err := s.service.RefreshToken(ctx, params)
	if err != nil {
		if errors.Is(err, service.ErrInvalidRefreshToken) ||
			errors.Is(err, service.ErrTokenNotFound) {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		logger.Log.Warn(op, "err", err)
		return nil, status.Error(codes.Internal, ErrInternal)
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
	params := dto.LogoutParams{
		RefreshToken: req.GetRefreshToken(),
	}
	_, err := s.service.Logout(ctx, params)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &authproto.LogoutResponse{
		Success: true,
	}, nil
}
