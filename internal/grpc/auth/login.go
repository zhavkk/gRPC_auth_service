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
	panic("todo")
}

func (s *serverAPI) ChangePassword(ctx context.Context, req *authproto.ChangePasswordRequest) (*authproto.ChangePasswordResponse, error) {
	if err := s.validator.ValidateChangePasswordRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	panic("todo")
}
