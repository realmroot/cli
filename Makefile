.PHONY: generate test verify build install

generate:
	test -n "$(REALMROOT_OPENAPI)"
	REALMROOT_OPENAPI="$(REALMROOT_OPENAPI)" go generate ./internal/realmrootapi

test:
	go test ./...

build:
	go build ./...

install:
	go build -o "$$(go env GOPATH)/bin/realmroot" .

verify: test build
