package producer

import "errors"

var (
	ErrMarshalUserCreated   = errors.New("marshal user-created event")
	ErrMarshalArtistCreated = errors.New("marshal artist-created event")
	ErrEmptyTopic           = errors.New("empty topic provided")
	ErrEmptyPayload         = errors.New("empty payload provided")
	ErrPublishFailed        = errors.New("failed to publish message")
	ErrBufferFull           = errors.New("kafka producer buffer is full, message not sent")
)
