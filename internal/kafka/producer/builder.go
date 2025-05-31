package producer

import (
	"encoding/json"
	"fmt"

	"github.com/zhavkk/gRPC_auth_service/internal/config"
	analyticsservice "github.com/zhavkk/gRPC_auth_service/internal/dto/kafka/analytics_service"
	"github.com/zhavkk/gRPC_auth_service/internal/models"
)

func BuildUserCreatedMessage(
	user *models.UserFull,
	topics config.KafkaTopics,
) (topic string, key string, payload []byte, err error) {
	const op = "kafka.BuildUserCreatedMessage"

	dto := analyticsservice.UserCreatedEvent{
		SchemaVersion: 1,
		ID:            user.ID.String(),
		Username:      user.Username,
		Gender:        user.Gender,
		Country:       user.Country,
		Age:           user.Age,
		Role:          user.Role,
		CreatedAt:     user.CreatedAt,
	}

	payload, err = json.Marshal(dto)
	if err != nil {
		err = fmt.Errorf("%s: marshal user created event: %w", op, err)
		return "", "", nil, err
	}
	topic = topics.UserCreatedTopic
	key = user.ID.String()

	return topic, key, payload, nil

}

func BuildArtistCreatedMessage(
	artist *models.ArtistFull,
	topics config.KafkaTopics,
) (topic string, key string, payload []byte, err error) {
	const op = "kafka.BuildArtistCreatedMessage"

	dto := analyticsservice.ArtistCreatedEvent{
		SchemaVersion: 1,
		ID:            artist.ID.String(),
		Username:      artist.Username,
		Producer:      artist.Producer,
		Country:       artist.Country,
		Description:   artist.Description,
		CreatedAt:     artist.CreatedAt,
	}
	payload, err = json.Marshal(dto)
	if err != nil {
		err = fmt.Errorf("%s: marshal artist created event: %w", op, err)
		return "", "", nil, err
	}
	topic = topics.ArtistCreatedTopic
	key = artist.ID.String()
	return topic, key, payload, nil
}
