package auth

import (
	"context"

	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
)

func (s *serverAPI) Login(ctx context.Context, req *authproto.LoginRequest) (*authproto.LoginResponse, error) {
	panic("todo")
}

func (s *serverAPI) ChangePassword(ctx context.Context, req *authproto.ChangePasswordRequest) (*authproto.ChangePasswordResponse, error) {
	panic("todo")
}
