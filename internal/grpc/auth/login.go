package auth

import (
	"context"

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
	resp, err := s.service.ChangePassword(ctx, req.GetId(), req.GetOldPassword(), req.GetNewPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	resp.Success = true

	return &authproto.ChangePasswordResponse{
		Success: resp.Success,
	}, nil
}
