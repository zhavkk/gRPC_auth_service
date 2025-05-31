// Package producer содержит интерфейс и реализацию для Kafka продюсера
package producer

import (
	"context"
	"sync"

	"github.com/IBM/sarama"

	"github.com/zhavkk/gRPC_auth_service/internal/config"
	"github.com/zhavkk/gRPC_auth_service/internal/logger"
	"github.com/zhavkk/gRPC_auth_service/internal/repository/postgres"
)

type KafkaProducer interface {
	Publish(
		ctx context.Context,
		topic string,
		key string,
		payload []byte,
		eventID int64,
	) error

	Close()
}

type SaramaProducer struct {
	asyncProducer sarama.AsyncProducer
	topics        config.KafkaTopics
	wg            sync.WaitGroup
	outboxRepo    *postgres.OutboxRepositoryPostgres
}

func NewSaramaProducer(
	cfg *config.KafkaConfig,
	topics config.KafkaTopics,
	outboxRepo *postgres.OutboxRepositoryPostgres,
) (*SaramaProducer, error) {
	const op = "kafka.NewSaramaProducer"
	saramaCfg, err := NewSaramaConfig(*cfg)
	if err != nil {
		return nil, err
	}
	producer, err := sarama.NewAsyncProducer(cfg.Brokers, saramaCfg)
	if err != nil {
		logger.Log.Error(op, "error", err)
		return nil, err
	}
	p := &SaramaProducer{
		asyncProducer: producer,
		topics:        topics,
		outboxRepo:    outboxRepo,
	}
	p.wg.Add(2)
	go p.handleSuccesses()
	go p.handleErrors()

	return p, nil
}

func (p *SaramaProducer) handleSuccesses() {
	const op = "kafka.SaramaProducer.handleSuccesses"
	defer p.wg.Done()
	for msg := range p.asyncProducer.Successes() {
		if id, ok := msg.Metadata.(int64); ok {
			_ = p.outboxRepo.MarkEventAsSent(
				context.Background(),
				id,
			)
		} else {
			logger.Log.Error(op, "unexpected metadata type", "metadata", msg.Metadata)
		}
	}
}

func (p *SaramaProducer) handleErrors() {
	const op = "kafka.SaramaProducer.handleErrors"
	defer p.wg.Done()
	for err := range p.asyncProducer.Errors() {
		logger.Log.Error(op, "error", err)
	}
}

func (p *SaramaProducer) Publish(
	ctx context.Context,
	topic, key string,
	payload []byte,
	eventID int64,
) error {
	msg := &sarama.ProducerMessage{
		Topic:    topic,
		Key:      sarama.StringEncoder(key),
		Value:    sarama.ByteEncoder(payload),
		Metadata: eventID,
	}
	select {
	case p.asyncProducer.Input() <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()

	}
}

func (p *SaramaProducer) Close() {
	p.asyncProducer.AsyncClose()
	p.wg.Wait()
	logger.Log.Info("Kafka producer closed successfully")
}
