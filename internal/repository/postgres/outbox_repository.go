package postgres

import (
	"context"
	"fmt"

	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/models"
	"github.com/zhavkk/gRPC_auth_service/internal/storage"
)

type OutboxRepositoryPostgres struct {
	storage   *storage.Storage
	txManager storage.TxManagerInterface
}

func NewOutboxRepository(
	storage *storage.Storage,
	txManager storage.TxManagerInterface,
) *OutboxRepositoryPostgres {
	return &OutboxRepositoryPostgres{
		storage:   storage,
		txManager: txManager,
	}
}

func (r *OutboxRepositoryPostgres) InsertEventTx(
	ctx context.Context,
	topic string,
	key string,
	payload []byte,
) error {
	const op = "outbox_repository.InsertEventTx"
	tx, ok := storage.GetTxFromContext(ctx)
	if !ok {
		return ErrNoTransactionInContext
	}
	quert := `
		INSERT INTO outbox_events (topic, key, payload)
		VALUES ($1, $2, $3)
	`
	_, err := tx.Exec(ctx, quert, topic, key, payload)
	logger.Log.Debug(op, "topic", topic, "key", key, "payload", string(payload))
	return err
}

func (r *OutboxRepositoryPostgres) FetchUnsentBatch(
	ctx context.Context,
	limit int,
) ([]*models.OutboxEvent, error) {
	const query = `
        SELECT id, topic, key, payload, created_at, sent, sent_at
          FROM outbox_events
         WHERE sent = false
      ORDER BY created_at
         LIMIT $1
      FOR UPDATE SKIP LOCKED
    `
	var events []*models.OutboxEvent

	err := r.txManager.RunReadCommited(ctx, func(ctx context.Context) error {
		tx, ok := storage.GetTxFromContext(ctx)
		if !ok {
			return ErrNoTransactionInContext
		}
		rows, err := tx.Query(ctx, query, limit)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var e models.OutboxEvent
			if err := rows.Scan(
				&e.ID, &e.Topic, &e.Key, &e.Payload,
				&e.CreatedAt, &e.Sent, &e.SentAt,
			); err != nil {
				return err
			}
			events = append(events, &e)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("FetchUnsentBatch: %w", err)
	}
	return events, nil
}

func (r *OutboxRepositoryPostgres) MarkEventAsSent(
	ctx context.Context,
	id int64,
) error {
	if id <= 0 {
		return fmt.Errorf("invalid event ID: %d", id)
	}
	query := `
		UPDATE outbox_events
		   SET sent = true, sent_at = now()
		 WHERE id = $1
	`
	_, err := r.storage.GetPool().Exec(ctx, query, id)
	return err
}
