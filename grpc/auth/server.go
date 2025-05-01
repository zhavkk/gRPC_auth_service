package auth

import (
	"context"

	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
	"google.golang.org/grpc"
)

type serverAPI struct {
	authproto.UnimplementedAuthServer
}

func Register(gRPC *grpc.Server) { // register handler
	authproto.RegisterAuthServer(gRPC, &serverAPI{})
}

func (s *serverAPI) Login(ctx context.Context, req *authproto.LoginRequest) (*authproto.LoginResponse, error) {

}
