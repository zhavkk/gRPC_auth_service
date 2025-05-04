package auth

import (
	"context"

	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *serverAPI) Register(ctx context.Context, req *authproto.RegisterRequest) (*authproto.RegisterResponse, error) {
	if err := s.validator.ValidateRegisterRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// logika s bd

	return &authproto.RegisterResponse{
		Id: "randomuuid",
	}, nil
}

func (s *serverAPI) GetUser(ctx context.Context, req *authproto.GetUserRequest) (*authproto.GetUserResponse, error) {
	if err := s.validator.ValidateGetUserRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	panic("todo")
}
