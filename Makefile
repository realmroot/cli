.PHONY: generate test verify build

generate:
	test -n "$(REALMROOT_OPENAPI)"
	REALMROOT_OPENAPI="$(REALMROOT_OPENAPI)" go generate ./internal/realmrootapi

test:
	go test ./...

build:
	go build ./cmd/realmroot

verify: test build

