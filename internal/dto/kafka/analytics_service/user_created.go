package analyticsservice

import "time"

type UserCreatedEvent struct {
	SchemaVersion int       `json:"schema_version"`
	ID            string    `json:"id"`
	Username      string    `json:"username"`
	Gender        bool      `json:"gender"`
	Country       string    `json:"country"`
	Age           int32     `json:"age"`
	Role          string    `json:"role"`
	CreatedAt     time.Time `json:"created_at"`
}
