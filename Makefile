.PHONY: all build test fmt vet clean

BINARY_NAME=goNetWatch

all: fmt vet test build

build:
	go build -o $(BINARY_NAME) ./cmd/goNetWatch

test:
	go test -v -cover ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY_NAME)
