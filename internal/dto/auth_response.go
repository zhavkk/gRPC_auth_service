package dto

import (
	"time"

	"github.com/zhavkk/gRPC_auth_service/internal/models"
)

type RegisterUserResponse struct {
	ID string
}

type RegisterArtistResponse struct {
	ID string
}

type LoginResponse struct {
	ID           string
	Username     string
	Role         models.Role
	AccessToken  string
	RefreshToken string
}

type GetUserResponse struct {
	ID        string
	Username  string
	Email     string
	Gender    bool
	Country   string
	Age       int32
	Role      models.Role
	CreatedAt time.Time
	UpdatedAt time.Time
}

type GetArtistResponse struct {
	ID          string
	Username    string
	Author      string
	Producer    string
	Country     string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type UpdateUserResponse struct {
	Success bool
}

type UpdateArtistResponse struct {
	Success bool
}

type ChangePasswordResponse struct {
	Success bool
}

type RefreshTokenResponse struct {
	AccessToken  string
	RefreshToken string
}

type LogoutResponse struct {
	Success bool
}
