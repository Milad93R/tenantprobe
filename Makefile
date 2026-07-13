# TenantProbe (Go) — single static binary.

BINARY ?= tenantprobe

.PHONY: build vet test integration clean

build:
	CGO_ENABLED=0 go build -trimpath -o $(BINARY) ./cmd/tenantprobe

vet:
	go vet ./...

test:
	go test -race ./...

integration: build
	./scripts/verify_pgvector.sh

clean:
	rm -f $(BINARY)
