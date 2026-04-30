BINARY  := stepsecurity-dev-machine-guard
MODULE  := github.com/step-security/dev-machine-guard
VERSION := $(shell grep -m1 'Version' internal/buildinfo/version.go | sed 's/.*"//;s/".*//')
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BRANCH  := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
TAG     := $(shell git describe --tags --exact-match 2>/dev/null || echo "dev")
LDFLAGS := -s -w \
	-X $(MODULE)/internal/buildinfo.GitCommit=$(COMMIT) \
	-X $(MODULE)/internal/buildinfo.ReleaseTag=$(TAG) \
	-X $(MODULE)/internal/buildinfo.ReleaseBranch=$(BRANCH)

.PHONY: build build-windows build-linux deploy-windows test lint clean smoke

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/stepsecurity-dev-machine-guard

build-windows:
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY).exe ./cmd/stepsecurity-dev-machine-guard

build-linux:
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-linux ./cmd/stepsecurity-dev-machine-guard

deploy-windows:
	@bash scripts/deploy-windows.sh $(DEPLOY_ARGS)

test:
	go test ./... -v -race -count=1

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY) $(BINARY).exe $(BINARY)-linux

smoke: build
	bash tests/test_smoke_go.sh
