package auth

import (
	"context"

	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *serverAPI) SetUserRole(ctx context.Context, req *authproto.SetUserRoleRequest) (*authproto.SetUserRoleResponse, error) {
	if err := s.validator.ValidateSetUserRoleRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	panic("todo")
}

func (s *serverAPI) UpdateUser(ctx context.Context, req *authproto.UpdateUserRequest) (*authproto.UpdateUserResponse, error) {
	if err := s.validator.ValidateUpdateUserRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	panic("todo")
}
