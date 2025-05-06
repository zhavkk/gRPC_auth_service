package auth

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *serverAPI) Login(ctx context.Context, req *authproto.LoginRequest) (*authproto.LoginResponse, error) {
	if err := s.validator.ValidateLoginRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	resp, err := s.service.Login(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &authproto.LoginResponse{
		Id:       resp.ID,
		Username: resp.Username,
		Email:    resp.Email,
		Role:     resp.Role,
		Token:    resp.Token,
	}, nil
}

func (s *serverAPI) ChangePassword(ctx context.Context, req *authproto.ChangePasswordRequest) (*authproto.ChangePasswordResponse, error) {
	if err := s.validator.ValidateChangePasswordRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	claims, ok := ctx.Value("claims").(jwt.MapClaims)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "claims not found")
	}

	userIDFromToken, ok := claims["uuid"].(string)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "invalid token claims")
	}

	// Проверяем, что пользователь меняет свой пароль
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
