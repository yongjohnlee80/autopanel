# AutoPanel. Tests run in a disposable container (tests never touch the
# developer's environment); build, vet and fmt run on the host.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/yongjohnlee80/autopanel/app.Version=$(VERSION)
GO      ?= go
GOIMAGE ?= golang:1.26
ARCH    ?= amd64
DIST    := bin/autopanel-$(VERSION)-linux-$(ARCH)
AGENT   := bin/autopanel-agent-$(VERSION)-linux-$(ARCH)

.PHONY: build build-linux dist dist-agent release vet fmt fmt-check test shellcheck check clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/autopanel ./cmd/autopanel

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/autopanel ./cmd/autopanel

# The release tarball install.sh downloads or runs from: binary, scripts and units side by
# side, with the checksum install.sh verifies.
dist: build-linux
	install -m 0755 install.sh uninstall.sh $(DIST)/
	install -m 0644 deploy/autopanel-core.service deploy/autopanel-gate.service deploy/autopanel-site.service deploy/autopanel.env.example $(DIST)/
	tar -C bin -czf $(DIST).tar.gz $(notdir $(DIST))
	cd bin && sha256sum $(notdir $(DIST)).tar.gz > $(notdir $(DIST)).tar.gz.sha256
	@echo $(DIST).tar.gz

# The tunnel agent's tarball: its binary and its unit, for the machine at the far end of a
# tunnel, which may be of another architecture than the server.
dist-agent:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(AGENT)/autopanel-agent ./cmd/autopanel-agent
	install -m 0644 deploy/autopanel-agent.service $(AGENT)/
	tar -C bin -czf $(AGENT).tar.gz $(notdir $(AGENT))
	cd bin && sha256sum $(notdir $(AGENT)).tar.gz > $(notdir $(AGENT)).tar.gz.sha256
	@echo $(AGENT).tar.gz

# Every tarball a release publishes (the release workflow runs this with VERSION set to the tag).
release:
	$(MAKE) dist ARCH=amd64
	$(MAKE) dist ARCH=arm64
	$(MAKE) dist-agent ARCH=amd64
	$(MAKE) dist-agent ARCH=arm64

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
