package domain

import (
	"time"
)

type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Gender    bool      `json:"gender"`
	Country   string    `json:"country"`
	Age       int32     `json:"age"`
	Role      string    `json:"role"`
	PassHash  string    `json:"passHash"`
	CreatedAt time.Time `json:"created_at"`
}

type RegisterResponse struct {
	ID string
}

type LoginResponse struct {
	ID       string
	Username string
	Email    string
	Role     string
	Token    string
}

type SetUserRoleResponse struct {
	ID   string
	Role string
}

type GetUserResponse struct {
	ID       string
	Username string
	Email    string
	Gender   bool
	Country  string
	Age      int32
	Role     string
}

type UpdateUserResponse struct {
	ID       string
	Username string
	Email    string
	Gender   bool
	Country  string
	Age      int32
	Role     string
}

type ChangePasswordResponse struct {
	Success bool
}
