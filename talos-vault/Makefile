# Talos Vault Build System (Updated)

PROTO_DIR := proto
BIN_DIR := bin
CONTROLLER_BIN := $(BIN_DIR)/controller
CLI_BIN := $(BIN_DIR)/talosctl

.PHONY: all init gen build run clean test

all: gen build

init:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

gen:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/*.proto

build:
	@echo "Building Controller & CLI..."
	mkdir -p $(BIN_DIR)
	go build -o $(CONTROLLER_BIN) cmd/controller/main.go
	go build -o $(CLI_BIN) cmd/talosctl/main.go
	@echo "Build complete."

run: build
	@echo "Starting Talos Vault Controller..."
	./$(CONTROLLER_BIN)

clean:
	rm -rf $(BIN_DIR) talos.db
