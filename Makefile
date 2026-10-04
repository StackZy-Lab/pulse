BINARY := pulse
PKG    := github.com/StackZy-Lab/pulse
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X $(PKG)/internal/cli.Version=$(VERSION)

.PHONY: build install test vet fmt clean run

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/pulse

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/pulse

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

run:
	go run ./cmd/pulse

clean:
	rm -f $(BINARY)
