.PHONY: all
all: verify

# The canonical gate. See devtools/verify for what each step checks.
.PHONY: verify
verify:
	@go run ./devtools/verify

.PHONY: fmt
fmt:
	@gofmt -w cmd internal devtools

# Formatting as a check, for editors and CI.
.PHONY: fmt-check
fmt-check:
	@test -z "$$(gofmt -l cmd internal devtools)" || { gofmt -l cmd internal devtools; exit 1; }

.PHONY: vet
vet:
	@go vet ./...

.PHONY: build
build:
	@go build ./...

.PHONY: test
test:
	@go test -count=1 ./...

# Unit tests only. No database, so it is safe to run anywhere.
.PHONY: test-short
test-short:
	@go test -count=1 -short ./...

.PHONY: test-race
test-race:
	@go test -count=1 -race ./internal/run/... ./internal/stage/... ./internal/net/... ./internal/scope/...

.PHONY: cover
cover:
	@go test -count=1 -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1

# Benchmarks are not part of the gate, because timings vary between machines.
# They are here so a hot-path change can be measured rather than guessed at.
.PHONY: bench
bench:
	@go test -run=XXX -bench=. -benchmem ./internal/...

# The authorization gate is the hot path: it runs once per candidate host and
# once per discovered URL.
.PHONY: bench-hot
bench-hot:
	@go test -run=XXX -bench='Gate|Explain|FilterURLs' -benchmem ./internal/...

# Version is taken from the current git tag, or a short commit when untagged.
# Releases set it the same way through GoReleaser.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build-binary
build-binary:
	@mkdir -p bin
	@go build -trimpath \
		-ldflags '-s -w -X github.com/BhargavPalan/Fal-X/internal/config.Version=$(VERSION)' \
		-o bin/fal-x ./cmd/fal-x
	@echo "built bin/fal-x $(VERSION)"

.PHONY: tidy
tidy:
	@go mod tidy
	@go mod verify

.PHONY: clean
clean:
	@rm -rf bin coverage.out