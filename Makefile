GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
BINARY  := ubuntu-pro-updates-exporter

.PHONY: all build test vet fmt lint lint-actions tidy snapshot clean

all: lint lint-actions test build

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) .

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w .

lint: vet
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi

lint-actions:
	@command -v actionlint >/dev/null || (echo "Install actionlint: https://github.com/rhysd/actionlint/blob/main/docs/install.md" && exit 1)
	@command -v zizmor >/dev/null || (echo "Install zizmor: https://docs.zizmor.sh/installation/" && exit 1)
	actionlint
	zizmor .

tidy:
	$(GO) mod tidy

snapshot:
	goreleaser build --snapshot --clean

clean:
	rm -rf $(BINARY) dist/
