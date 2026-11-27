# encoding/json/v2 + jsontext are available without GOEXPERIMENT on Go 1.27.4.
# If you build with an older toolchain, run: make GOEXPERIMENT=jsonv2 build
BIN := bin/docker-socket-secure-proxy
export CGO_ENABLED := 0

.PHONY: build test vet e2e clean
build:
	go build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/docker-socket-secure-proxy
	@file $(BIN)

test:
	CGO_ENABLED=1 go test -race ./...

vet:
	go vet ./...

e2e: build
	./scripts/e2e.sh

clean:
	rm -rf bin
