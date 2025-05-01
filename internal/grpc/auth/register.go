package auth

import (
	"context"

	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
)

func (s *serverAPI) Register(ctx context.Context, req *authproto.RegisterRequest) (*authproto.RegisterResponse, error) {
	panic("todo")
}

func (s *serverAPI) GetUser(ctx context.Context, req *authproto.GetUserRequest) (*authproto.GetUserResponse, error) {
	panic("todo")
}
