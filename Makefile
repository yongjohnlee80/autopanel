# AutoPanel. Tests run in a disposable container (tests never touch the
# developer's environment); build, vet and fmt run on the host.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/yongjohnlee80/autopanel/app.Version=$(VERSION)
GO      ?= go
GOIMAGE ?= golang:1.26
DIST    := bin/autopanel-$(VERSION)-linux-amd64

.PHONY: build build-linux dist vet fmt fmt-check test shellcheck check clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/autopanel ./cmd/autopanel

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/autopanel ./cmd/autopanel

# The release tarball install.sh downloads or runs from: binary, scripts and unit side by
# side, with the checksum install.sh verifies.
dist: build-linux
	install -m 0755 install.sh uninstall.sh $(DIST)/
	install -m 0644 deploy/autopanel.service deploy/autopanel.env.example $(DIST)/
	tar -C bin -czf $(DIST).tar.gz $(notdir $(DIST))
	cd bin && sha256sum $(notdir $(DIST)).tar.gz > $(notdir $(DIST)).tar.gz.sha256
	@echo $(DIST).tar.gz

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

fmt-check:
	test -z "$$(gofmt -l .)"

test:
	docker run --rm -v "$(CURDIR)":/src:ro -w /src -e GOFLAGS=-mod=readonly \
	  -e HOME=/tmp/home -e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomod \
	  $(GOIMAGE) go test -count=1 -race ./...

shellcheck:
	shellcheck -s sh install.sh uninstall.sh

check: fmt-check vet shellcheck test

clean:
	rm -rf bin coverage.out
