// Package dto содержит параметры для входных данных.
package dto

type RegisterUserParams struct {
	Username string
	Email    string
	Password string
	Gender   bool
	Country  string
	Age      int32
}

type RegisterArtistParams struct {
	Username    string
	Password    string
	Author      string
	Producer    string
	Country     string
	Description string
}

type LoginParams struct {
	Username string
	Password string
}

type GetUserParams struct {
	ID string
}

type GetArtistParams struct {
	ID string
}

type UpdateUserParams struct {
	ID       string
	Username string
	Country  string
	Age      int32
}
type UpdateArtistParams struct {
	ID          string
	Author      string
	Producer    string
	Country     string
	Description string
}

type ChangePasswordParams struct {
	ID          string
	OldPassword string
	NewPassword string
}

type RefreshTokenParams struct {
	RefreshToken string
}

type LogoutParams struct {
	RefreshToken string
}
