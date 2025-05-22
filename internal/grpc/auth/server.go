package auth

import (
	"context"

	"google.golang.org/grpc"

	"github.com/zhavkk/gRPC_auth_service/internal/dto"
	"github.com/zhavkk/gRPC_auth_service/internal/validation"
	authproto "github.com/zhavkk/gRPC_auth_service/pkg/authpb"
)

type AuthService interface {
	RegisterUser(
		ctx context.Context,
		req dto.RegisterUserParams,
	) (*dto.RegisterUserResponse, error)

	RegisterArtist(
		ctx context.Context,
		req dto.RegisterArtistParams,
	) (*dto.RegisterArtistResponse, error)
	Login(
		ctx context.Context,
		req dto.LoginParams,
	) (*dto.LoginResponse, error)

	GetUser(
		ctx context.Context,
		req dto.GetUserParams,
	) (*dto.GetUserResponse, error)
	GetArtist(
		ctx context.Context,
		req dto.GetArtistParams,
	) (*dto.GetArtistResponse, error)
	UpdateUser(
		ctx context.Context,
		req dto.UpdateUserParams,
	) (*dto.UpdateUserResponse, error)
	UpdateArtist(
		ctx context.Context,
		req dto.UpdateArtistParams,
	) (*dto.UpdateArtistResponse, error)

	ChangePassword(
		ctx context.Context,
		req dto.ChangePasswordParams,
	) (*dto.ChangePasswordResponse, error)
	RefreshToken(
		ctx context.Context,
		req dto.RefreshTokenParams,
	) (*dto.RefreshTokenResponse, error)
	Logout(
		ctx context.Context,
		req dto.LogoutParams,
	) (*dto.LogoutResponse, error)
}

type serverAPI struct {
	authproto.UnimplementedAuthServiceServer
	validator validation.Validator
	service   AuthService
}

func Register(gRPC *grpc.Server,
	service AuthService,
) {
	authproto.RegisterAuthServiceServer(gRPC, &serverAPI{
		validator: validation.NewValidator(),
		service:   service,
	})
}
