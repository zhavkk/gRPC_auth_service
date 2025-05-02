package auth

import (
	"context"
	"fmt"

	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
)

func (s *serverAPI) Register(ctx context.Context, req *authproto.RegisterRequest) (*authproto.RegisterResponse, error) {
	fmt.Print("testik")
	return &authproto.RegisterResponse{
		Id: "1",
	}, nil
}

func (s *serverAPI) GetUser(ctx context.Context, req *authproto.GetUserRequest) (*authproto.GetUserResponse, error) {
	panic("todo")
}
