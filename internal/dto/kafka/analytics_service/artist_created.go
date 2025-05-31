// Package analyticsservice содержит DTO для событий аналитики
package analyticsservice

import "time"

type ArtistCreatedEvent struct {
	SchemaVersion int       `json:"schema_version"`
	ID            string    `json:"id"`
	Username      string    `json:"name"`
	Producer      string    `json:"producer"`
	Country       string    `json:"country"`
	Description   string    `json:"description"`
	CreatedAt     time.Time `json:"created_at"`
}
