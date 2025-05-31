-- +goose Up
-- +goose StatementBegin
CREATE TABLE outbox_events (
  id         BIGSERIAL PRIMARY KEY,
  topic      TEXT       NOT NULL,
  key        TEXT,
  payload    JSONB      NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  sent       BOOLEAN    DEFAULT false,
  sent_at    TIMESTAMPTZ
);
CREATE INDEX idx_outbox_unsent ON outbox_events(sent) WHERE sent = false;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_outbox_events_aggregate_id;
DROP INDEX IF EXISTS idx_outbox_events_created_at;
DROP INDEX IF EXISTS idx_outbox_events_processed_at;
DROP TABLE IF EXISTS outbox_events;
-- +goose StatementEnd
