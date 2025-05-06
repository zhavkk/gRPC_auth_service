package auth

import (
	"context"

	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
	"github.com/zhavkk/gRPC_auth_service/internal/domain"
	"github.com/zhavkk/gRPC_auth_service/internal/validation"
	"google.golang.org/grpc"
)

type AuthService interface {
	Register(
		ctx context.Context,
		username string,
		email string,
		password string,
		gender bool,
		country string,
		age int32,
		role string,
	) (*domain.RegisterResponse, error)

	Login(
		ctx context.Context,
		email string,
		password string,
	) (*domain.LoginResponse, error)

	SetUserRole(
		ctx context.Context,
		id string,
		role string,
	) (*domain.SetUserRoleResponse, error)

	GetUser(
		ctx context.Context,
		id string,
	) (*domain.GetUserResponse, error)

	UpdateUser(
		ctx context.Context,
		id string,
		username string,
		country string,
		age int32,
	) (*domain.UpdateUserResponse, error)

	ChangePassword(
		ctx context.Context,
		id string,
		oldPassword string,
		newPassword string,
	) (*domain.ChangePasswordResponse, error)
}

type serverAPI struct {
	authproto.UnimplementedAuthServer
	validator validation.Validator
	service   AuthService
}

func Register(gRPC *grpc.Server, service AuthService) { // register handler
	authproto.RegisterAuthServer(gRPC, &serverAPI{
		validator: validation.NewValidator(),
		service:   service,
	})
}
