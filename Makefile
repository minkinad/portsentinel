.PHONY: setup build run test lint fmt check docker-build
setup:
	go mod download
build:
	go build -o bin/portsentinel ./cmd/portsentinel
	go build -o bin/portsentinel-server ./cmd/portsentinel-server
run:
	go run ./cmd/portsentinel-server --config configs/portsentinel.yaml
test:
	go test ./...
lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.5.0 run ./...
fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')
check:
	go vet ./...
	go test -race ./...
docker-build:
	docker build -t portsentinel:dev .
