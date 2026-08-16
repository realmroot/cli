.PHONY: generate test verify build install release-check

VERSION ?= dev
COMMIT ?= $(shell git describe --always --dirty 2>/dev/null)
BUILD_TIME ?=
LDFLAGS := -X github.com/realmroot/cli/internal/buildinfo.Version=$(VERSION) -X github.com/realmroot/cli/internal/buildinfo.Commit=$(COMMIT) -X github.com/realmroot/cli/internal/buildinfo.BuildTime=$(BUILD_TIME)

generate:
	test -n "$(REALMROOT_OPENAPI)"
	REALMROOT_OPENAPI="$(REALMROOT_OPENAPI)" go generate ./internal/realmrootapi

test:
	go test ./...

build:
	go build -ldflags "$(LDFLAGS)" ./...

install:
	go build -ldflags "$(LDFLAGS)" -o "$$(go env GOPATH)/bin/realmroot" .

release-check:
	goreleaser check
	goreleaser release --snapshot --clean

verify: test build
