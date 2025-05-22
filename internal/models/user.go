// Package models содержит базовые ошибки и доменные сущности для auth-сервиса.
package models

import (
	"time"

	"github.com/google/uuid"
)

type Profile struct {
	ID        uuid.UUID `db:"id"`
	Username  string    `db:"username"`
	PassHash  string    `db:"pass_hash"`
	Role      string    `db:"role"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

type User struct {
	ProfileID uuid.UUID `db:"profile_id"`
	Email     string    `db:"email"`
	Gender    bool      `db:"gender"`
	Country   string    `db:"country"`
	Age       int32     `db:"age"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

type Artist struct {
	ProfileID   uuid.UUID `db:"profile_id"`
	Author      string    `db:"author"`
	Producer    string    `db:"producer"`
	Country     string    `db:"country"`
	Description string    `db:"description"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

type UserFull struct {
	ID        uuid.UUID `db:"id"`
	Username  string    `db:"username"`
	Role      string    `db:"role"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`

	Email   string `db:"email" `
	Gender  bool   `db:"gender" `
	Country string `db:"country"`
	Age     int32  `db:"age" `
}

type ArtistFull struct {
	ID        uuid.UUID `db:"id"`
	Username  string    `db:"username"`
	Role      string    `db:"role"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`

	Author      string `db:"author"`
	Producer    string `db:"producer"`
	Country     string `db:"country"`
	Description string `db:"description"`
}
