package auth

import (
	"context"

	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
	"google.golang.org/grpc"

	"github.com/zhavkk/gRPC_auth_service/internal/models"
	"github.com/zhavkk/gRPC_auth_service/internal/validation"
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
	) (*models.RegisterResponse, error)

	Login(
		ctx context.Context,
		email string,
		password string,
	) (*models.LoginResponse, error)

	SetUserRole(
		ctx context.Context,
		id string,
		role string,
	) (*models.SetUserRoleResponse, error)

	GetUser(
		ctx context.Context,
		id string,
	) (*models.GetUserResponse, error)

	UpdateUser(
		ctx context.Context,
		id string,
		username string,
		country string,
		age int32,
	) (*models.UpdateUserResponse, error)

	ChangePassword(
		ctx context.Context,
		id string,
		oldPassword string,
		newPassword string,
	) (*models.ChangePasswordResponse, error)
}

type serverAPI struct {
	authproto.UnimplementedAuthServer
	validator validation.Validator
	service   AuthService
}

func Register(gRPC *grpc.Server,
	service AuthService,
) {
	authproto.RegisterAuthServer(gRPC, &serverAPI{
		validator: validation.NewValidator(),
		service:   service,
	})
}
