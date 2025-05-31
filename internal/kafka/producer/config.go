package producer

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/IBM/sarama"

	"github.com/zhavkk/gRPC_auth_service/internal/config"
)

func NewSaramaConfig(
	kcfg config.KafkaConfig,
) (*sarama.Config, error) {
	cfg := sarama.NewConfig()

	version, err := sarama.ParseKafkaVersion(kcfg.Version)
	if err != nil {
		return nil, err
	}
	cfg.Version = version

	cfg.ClientID = kcfg.ClientID

	cfg.Producer.RequiredAcks = sarama.WaitForAll
	cfg.Producer.Idempotent = true
	cfg.Producer.Retry.Max = kcfg.Retries
	cfg.Producer.Retry.Backoff = kcfg.RetryBackoff
	cfg.Net.MaxOpenRequests = 1
	cfg.Producer.Flush.Frequency = kcfg.FlushFrequency
	cfg.Producer.Return.Successes = true
	cfg.Producer.Return.Errors = true

	switch strings.ToLower(kcfg.Compression) {
	case "gzip":
		cfg.Producer.Compression = sarama.CompressionGZIP
	case "zstd":
		cfg.Producer.Compression = sarama.CompressionZSTD
	case "lz4":
		cfg.Producer.Compression = sarama.CompressionLZ4
	default:
		cfg.Producer.Compression = sarama.CompressionSnappy
	}

	if kcfg.TLS.Enable {
		tlsCfg, err := loadTLSConfig(kcfg.TLS.CACert, kcfg.TLS.Cert, kcfg.TLS.Key)
		if err != nil {
			return nil, fmt.Errorf("load TLS config: %w", err)
		}
		cfg.Net.TLS.Enable = true
		cfg.Net.TLS.Config = tlsCfg
	}

	return cfg, nil

}

func loadTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert file %q: %w", caFile, err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to append CA certs from %q", caFile)
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read client cert file %q: %w", certFile, err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read client key file %q: %w", keyFile, err)
	}
	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client key pair (%q, %q): %w", certFile, keyFile, err)
	}

	tlsCfg := &tls.Config{
		RootCAs:            caPool,
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: false,
	}

	return tlsCfg, nil
}
