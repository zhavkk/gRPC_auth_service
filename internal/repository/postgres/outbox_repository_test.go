package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/zhavkk/gRPC_auth_service/internal/config"
	"github.com/zhavkk/gRPC_auth_service/internal/models"
	"github.com/zhavkk/gRPC_auth_service/internal/storage"
)

type OutboxRepositorySuite struct {
	suite.Suite
	pool             *pgxpool.Pool
	store            *storage.Storage
	txManager        *storage.TxManager
	outboxRepository *OutboxRepositoryPostgres
	ctx              context.Context
	insertedEventID  int64
}

func TestOutboxRepository(t *testing.T) {
	suite.Run(t, new(OutboxRepositorySuite))
}

func (s *OutboxRepositorySuite) SetupSuite() {
	s.ctx = context.Background()

	dsn := "postgres://testuser:testpass@localhost:5432/auth_db?sslmode=disable"
	var err error
	s.pool, err = pgxpool.New(s.ctx, dsn)
	require.NoError(s.T(), err, "Failed to connect to test database")

	cfg := &config.Config{
		DBURL: dsn,
	}
	s.store, err = storage.NewStorage(s.ctx, cfg)
	require.NoError(s.T(), err, "Failed to create storage")

	s.txManager, err = storage.NewTxManager(s.ctx, cfg)
	require.NoError(s.T(), err, "Failed to create transaction manager")

	s.outboxRepository = NewOutboxRepository(s.store, s.txManager)

	_, err = s.pool.Exec(s.ctx, "TRUNCATE outbox_events RESTART IDENTITY CASCADE")
	require.NoError(s.T(), err, "Failed to truncate outbox_events table")
}

func (s *OutboxRepositorySuite) TearDownSuite() {
	s.pool.Close()
}

func (s *OutboxRepositorySuite) BeforeTest(_, _ string) {
	_, err := s.pool.Exec(s.ctx, "TRUNCATE outbox_events RESTART IDENTITY CASCADE")
	require.NoError(s.T(), err, "Failed to truncate outbox_events table")

	var id int64
	err = s.pool.QueryRow(
		s.ctx,
		`INSERT INTO outbox_events (topic, key, payload, sent) VALUES ($1, $2, $3, $4) RETURNING id`,
		"test-topic", "test-key", []byte(`{"data":"test"}`), false,
	).Scan(&id)
	require.NoError(s.T(), err, "Failed to insert test event")
	s.insertedEventID = id
}

func (s *OutboxRepositorySuite) TestInsertEventTx() {
	var topic string = "user-created"
	var key string = "user-123"
	var payload []byte = []byte(`{"user_id":"123","username":"test_user"}`)
	var err error

	err = s.txManager.RunReadCommited(s.ctx, func(ctxWithTx context.Context) error {
		return s.outboxRepository.InsertEventTx(ctxWithTx, topic, key, payload)
	})
	require.NoError(s.T(), err, "InsertEventTx should not return an error")

	var count int
	err = s.pool.QueryRow(s.ctx,
		"SELECT COUNT(*) FROM outbox_events WHERE topic = $1 AND key = $2",
		topic, key).Scan(&count)
	require.NoError(s.T(), err, "Failed to count events")
	assert.Equal(s.T(), 1, count, "One event should be inserted")

	var event models.OutboxEvent
	err = s.pool.QueryRow(
		s.ctx,
		"SELECT id, topic, key, payload, created_at, sent, sent_at FROM outbox_events WHERE topic = $1 AND key = $2",
		topic, key,
	).Scan(
		&event.ID,
		&event.Topic,
		&event.Key,
		&event.Payload,
		&event.CreatedAt,
		&event.Sent,
		&event.SentAt,
	)
	require.NoError(s.T(), err, "Failed to fetch inserted event")

	assert.Equal(s.T(), topic, event.Topic, "Topic should match")
	assert.Equal(s.T(), key, event.Key.String, "Key should match")

	var payloadMap map[string]interface{}
	var eventPayloadMap map[string]interface{}
	err = json.Unmarshal(payload, &payloadMap)
	require.NoError(s.T(), err, "Failed to unmarshal expected payload")
	err = json.Unmarshal(event.Payload, &eventPayloadMap)
	require.NoError(s.T(), err, "Failed to unmarshal actual payload")

	assert.Equal(s.T(), payloadMap["user_id"], eventPayloadMap["user_id"], "user_id should match")
	assert.Equal(s.T(), payloadMap["username"], eventPayloadMap["username"], "username should match")

	assert.False(s.T(), event.Sent, "Event should not be marked as sent")
	assert.False(s.T(), event.SentAt.Valid, "SentAt should be NULL")
}

func (s *OutboxRepositorySuite) TestInsertEventTxNoTransaction() {
	err := s.outboxRepository.InsertEventTx(s.ctx, "topic", "key", []byte(`{"test":"data"}`))
	require.Error(s.T(), err, "InsertEventTx should return an error when no transaction in context")
	assert.ErrorIs(s.T(), err, ErrNoTransactionInContext, "Error should be ErrNoTransactionInContext")
}

func (s *OutboxRepositorySuite) TestFetchUnsentBatch() {
	_, err := s.pool.Exec(
		s.ctx,
		`INSERT INTO outbox_events (topic, key, payload, sent) VALUES 
         ($1, $2, $3, $4),
         ($5, $6, $7, $8),
         ($9, $10, $11, $12)`,
		"topic-1", "key-1", []byte(`{"id":"1"}`), false,
		"topic-2", "key-2", []byte(`{"id":"2"}`), false,
		"topic-3", "key-3", []byte(`{"id":"3"}`), true,
	)
	require.NoError(s.T(), err, "Failed to insert test events")

	events, err := s.outboxRepository.FetchUnsentBatch(s.ctx, 10)
	require.NoError(s.T(), err, "FetchUnsentBatch should not return an error")

	assert.Len(s.T(), events, 3, "Should fetch 3 unsent events")

	for _, event := range events {
		assert.False(s.T(), event.Sent, "Only unsent events should be fetched")
	}

	limitedEvents, err := s.outboxRepository.FetchUnsentBatch(s.ctx, 2)
	require.NoError(s.T(), err, "FetchUnsentBatch with limit should not return an error")
	assert.Len(s.T(), limitedEvents, 2, "Should fetch only 2 events when limited")
}
func (s *OutboxRepositorySuite) TestMarkEventAsSent() {
	err := s.outboxRepository.MarkEventAsSent(s.ctx, s.insertedEventID)
	require.NoError(s.T(), err, "MarkEventAsSent should not return an error")

	var sent bool
	var sentAt sql.NullTime
	err = s.pool.QueryRow(s.ctx,
		"SELECT sent, sent_at FROM outbox_events WHERE id = $1",
		s.insertedEventID).Scan(&sent, &sentAt)
	require.NoError(s.T(), err, "Failed to fetch marked event")

	assert.True(s.T(), sent, "Event should be marked as sent")
	assert.True(s.T(), sentAt.Valid, "SentAt should have a value")
	assert.WithinDuration(s.T(), time.Now(), sentAt.Time, 5*time.Second, "SentAt should be set to recent time")

	err = s.outboxRepository.MarkEventAsSent(s.ctx, 0)
	require.Error(s.T(), err, "MarkEventAsSent should return an error for invalid ID")
	assert.Contains(s.T(), err.Error(), "invalid event ID", "Error should indicate invalid ID")
}
