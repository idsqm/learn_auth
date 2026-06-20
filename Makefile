.PHONY: run build test migrate-up migrate-down migrate-create docker-up docker-down

include .env
export

DEV=docker compose --profile tools run --rm dev
GOOSE=$(DEV) go run github.com/pressly/goose/v3/cmd/goose@latest
DB_URL_DOCKER=postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@postgres:5432/$(POSTGRES_DB)?sslmode=disable

run:
	docker compose up -d --build --force-recreate

build:
	docker compose build

test:
	$(DEV) go test ./... -v -count=1

migrate-up:
	$(GOOSE) -dir migrations postgres "$(DB_URL_DOCKER)" up

migrate-down:
	$(GOOSE) -dir migrations postgres "$(DB_URL_DOCKER)" down

migrate-create:
	$(GOOSE) -dir migrations create $(name) sql

docker-up:
	docker compose up -d

docker-down:
	docker compose down
