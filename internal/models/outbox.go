package models

import (
	"database/sql"
	"time"
)

type OutboxEvent struct {
	ID        int64
	Topic     string
	Key       sql.NullString
	Payload   []byte
	CreatedAt time.Time
	Sent      bool
	SentAt    sql.NullTime
}
