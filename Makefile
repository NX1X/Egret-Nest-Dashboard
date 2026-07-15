# Egret Nest Dashboard — build & dev tasks. Pure Go, no CGO, no kernel.

BINARY  := egret-nest
CMD     := ./cmd/egret-nest
BIN_DIR := bin

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build run test cover vet fmt tidy lint docker clean

all: build

## build: single static binary (embedded UI + pure-Go SQLite).
build:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD)

## run: build and run locally on :8080.
run:
	go run $(CMD)

## test / cover: unit tests (no kernel, any OS).
test:
	go test ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1
	go tool cover -html=coverage.out -o coverage.html

vet:
	go vet ./...

fmt:
	gofmt -s -w .

tidy:
	go mod tidy

lint: vet
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "gofmt: files need formatting" && exit 1)

## docker: build the container image.
docker:
	docker build -t egret-nest:$(VERSION) .

clean:
	rm -rf $(BIN_DIR) coverage.out coverage.html *.db
