package models

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
