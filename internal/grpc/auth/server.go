package auth

import (
	"context"

	authproto "github.com/zhavkk/Auth-protobuf/gen/go/auth"
	"github.com/zhavkk/gRPC_auth_service/internal/validation"
	"google.golang.org/grpc"
)

type AuthService interface {
	// Register регистрирует нового пользователя
	Register(
		ctx context.Context,
		username string,
		email string,
		password string,
		gender bool,
		country string,
		age int32,
	) (*RegisterResponse, error)

	// Login выполняет вход пользователя
	Login(
		ctx context.Context,
		email string,
		password string,
	) (*LoginResponse, error)

	// SetUserRole устанавливает роль пользователя
	SetUserRole(
		ctx context.Context,
		id string,
		role string,
	) (*SetUserRoleResponse, error)

	// GetUser получает информацию о пользователе
	GetUser(
		ctx context.Context,
		id string,
	) (*GetUserResponse, error)

	// UpdateUser обновляет информацию о пользователе
	UpdateUser(
		ctx context.Context,
		id string,
		username string,
		country string,
		age int32,
	) (*UpdateUserResponse, error)

	// ChangePassword изменяет пароль пользователя
	ChangePassword(
		ctx context.Context,
		id string,
		oldPassword string,
		newPassword string,
	) (*ChangePasswordResponse, error)
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
