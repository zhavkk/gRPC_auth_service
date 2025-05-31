// Package outbox содержит реализацию worker-а для обработки событий из outbox и их публикации в Kafka.
package outbox

import (
	"context"
	"log/slog"
	"time"

	"github.com/zhavkk/gRPC_auth_service/internal/kafka/producer"
	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/models"
	"github.com/zhavkk/gRPC_auth_service/internal/service"
)

type OutboxWorker interface {
	Start(ctx context.Context)
}

type Worker struct {
	outboxRepository service.OutboxRepository
	kafkaProducer    producer.KafkaProducer
	batchSize        int
	pollInterval     time.Duration
}

func NewWorker(
	outboxRepository service.OutboxRepository,
	kafkaProducer producer.KafkaProducer,
	batchSize int,
	pollInterval time.Duration,
) *Worker {
	return &Worker{
		outboxRepository: outboxRepository,
		kafkaProducer:    kafkaProducer,
		batchSize:        batchSize,
		pollInterval:     pollInterval,
	}
}

func (w *Worker) Start(ctx context.Context) {
	const op = "outbox.Worker.Start"
	logger.Log.Info(op, "batchSize", w.batchSize, "pollInterval", w.pollInterval)
	logger.Log.Info("Starting outbox worker", "op", op)

	interval := w.pollInterval

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Log.Info("Stopping outbox worker", slog.String("op", op))
			return
		case <-ticker.C:
			if err := w.processBatch(ctx); err != nil {
				logger.Log.Error("Failed to process outbox batch",
					slog.String("op", op),
					slog.String("error", err.Error()))
			}
		}
	}

}
func (w *Worker) processBatch(ctx context.Context) error {
	const op = "outbox.Worker.processBatch"

	events, err := w.outboxRepository.FetchUnsentBatch(ctx, w.batchSize)
	if err != nil {
		logger.Log.Error("Failed to fetch unsent batch",
			slog.String("op", op),
			slog.String("error", err.Error()))
		return err
	}

	logger.Log.Debug("Outbox batch check",
		slog.String("op", op),
		slog.Int("events_count", len(events)))

	if len(events) == 0 {
		return nil
	}

	logger.Log.Info("Processing outbox batch",
		slog.String("op", op),
		slog.Int("count", len(events)))
	for _, event := range events {
		var processErr error
		const maxRetries = 3

		for attempt := 1; attempt <= maxRetries; attempt++ {
			processErr = w.processEvent(ctx, event)
			if processErr == nil {
				break
			}

			logger.Log.Error("Failed to process event",
				slog.String("op", op),
				slog.Int64("event_id", event.ID),
				slog.String("topic", event.Topic),
				slog.Int("attempt", attempt),
				slog.String("error", processErr.Error()))
			if attempt < maxRetries {
				time.Sleep(100 * time.Millisecond * time.Duration(attempt))
			}
		}

		if processErr != nil {
			logger.Log.Error("Failed to process event after all retries",
				slog.String("op", op),
				slog.Int64("event_id", event.ID),
				slog.String("topic", event.Topic),
				slog.String("error", processErr.Error()))
			continue
		}
		logger.Log.Debug("Event processed successfully",
			slog.String("op", op),
			slog.Int64("event_id", event.ID),
			slog.String("topic", event.Topic))

	}
	return nil
}

func (w *Worker) processEvent(ctx context.Context, event *models.OutboxEvent) error {
	const op = "outbox.Worker.processEvent"

	key := ""
	if event.Key.Valid {
		key = event.Key.String
	}

	if event.Topic == "" {
		logger.Log.Error("Empty topic in event",
			slog.String("op", op),
			slog.Int64("event_id", event.ID))
		return producer.ErrEmptyTopic
	}

	if len(event.Payload) == 0 {
		logger.Log.Error("Empty payload in event",
			slog.String("op", op),
			slog.Int64("event_id", event.ID),
			slog.String("topic", event.Topic))
		return producer.ErrEmptyPayload
	}

	logger.Log.Info("Publishing event to Kafka",
		slog.String("op", op),
		slog.Int64("event_id", event.ID),
		slog.String("topic", event.Topic),
		slog.String("key", key),
		slog.String("payload", string(event.Payload)),
	)
	err := w.kafkaProducer.Publish(ctx, event.Topic, key, event.Payload, event.ID)
	if err != nil {
		logger.Log.Error("Failed to publish event to Kafka",
			slog.String("op", op),
			slog.Int64("event_id", event.ID),
			slog.String("topic", event.Topic),
			slog.String("error", err.Error()))
	} else {
		logger.Log.Info("Successfully published event to Kafka",
			slog.String("op", op),
			slog.Int64("event_id", event.ID),
			slog.String("topic", event.Topic))
	}

	return err
}
