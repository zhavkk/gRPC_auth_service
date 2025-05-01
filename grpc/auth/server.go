package auth

import auth "github.com/zhavkk/Auth-protobuf/gen/go/auth"

type serverAPI struct {
	auth.UnimplementedAuthServer
}
