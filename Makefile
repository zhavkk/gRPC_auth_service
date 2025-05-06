# Переменные
MIGRATIONS_DIR = migrations
DB_URL ?= $(shell grep DB_URL .env | cut -d '=' -f2)
BINARY_NAME = auth_service

# Миграции
.PHONY: migrate-up
migrate-up:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DB_URL)" up

.PHONY: migrate-down
migrate-down:
	goose -dir $(MIGRATIONS_DIR) postgres "$(DB_URL)" down

# Сборка
.PHONY: build
build:
	go build -o $(BINARY_NAME) ./cmd/main

# Запуск
.PHONY: run
run:
	go run ./cmd/main

# Тесты
.PHONY: test
test:
	go test -v ./...

# Очистка
.PHONY: clean
clean:
	rm -f $(BINARY_NAME)