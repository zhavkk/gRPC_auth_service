package auth

import (
	"context"

	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
)

func (s *serverAPI) SetUsetRole(ctx context.Context, req *authproto.SetUserRoleRequest) (*authproto.SetUserRoleResponse, error) {
	panic("todo")
}

func (s *serverAPI) UpdateUser(ctx context.Context, req *authproto.UpdateUserRequest) (*authproto.UpdateUserResponse, error) {
	panic("todo")
}
