package auth

import (
	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
	"github.com/zhavkk/gRPC_auth_service/internal/validation"
	"google.golang.org/grpc"
)

type serverAPI struct {
	authproto.UnimplementedAuthServer
	validator validation.Validator
}

func Register(gRPC *grpc.Server) { // register handler
	authproto.RegisterAuthServer(gRPC, &serverAPI{
		validator: validation.NewValidator(),
	})
}
