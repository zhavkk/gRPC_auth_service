MIGRATIONS_DIR ?= ./migrations
DB_URL ?= postgres://testuser:testpass@localhost:5432/testdb?sslmode=disable

.PHONY: migrate-up
migrate-up:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DB_URL)" up

.PHONY: migrate-down
migrate-down:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DB_URL)" down
