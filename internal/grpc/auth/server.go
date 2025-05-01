package auth

import (
	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
	"google.golang.org/grpc"
)

type serverAPI struct {
	authproto.UnimplementedAuthServer
}

func Register(gRPC *grpc.Server) { // register handler
	authproto.RegisterAuthServer(gRPC, &serverAPI{})
}
