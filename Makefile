# TenantProbe (Go) — single static binary.
#
# The output binary is named `tp` rather than `tenantprobe` because the Python
# v0.1 package already occupies the `tenantprobe/` directory in this repo.

BINARY ?= tp

.PHONY: build vet test clean

build:
	CGO_ENABLED=0 go build -o $(BINARY) ./cmd/tenantprobe

vet:
	go vet ./...

test:
	go test ./...

clean:
	rm -f $(BINARY) tp-bin
