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

.PHONY: build build-windows build-windows-task build-windows-arm64 build-windows-task-arm64 build-linux deploy-windows test lint clean smoke build-msi-amd64 build-msi-arm64

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/stepsecurity-dev-machine-guard

build-windows:
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY).exe ./cmd/stepsecurity-dev-machine-guard

# GUI-subsystem launcher (see cmd/stepsecurity-dev-machine-guard-task).
# `-H windowsgui` flips the PE subsystem so Windows doesn't allocate
# a console when Task Scheduler launches it.
build-windows-task:
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS) -H windowsgui" -o $(BINARY)-task.exe ./cmd/stepsecurity-dev-machine-guard-task

build-windows-arm64:
	GOOS=windows GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-arm64.exe ./cmd/stepsecurity-dev-machine-guard

build-windows-task-arm64:
	GOOS=windows GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS) -H windowsgui" -o $(BINARY)-task-arm64.exe ./cmd/stepsecurity-dev-machine-guard-task

build-linux:
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-linux ./cmd/stepsecurity-dev-machine-guard

# MSI builds. Require WiX 4 on PATH: `dotnet tool install --global wix --version 4.0.5`.
# Output: dist/stepsecurity-dev-machine-guard-<version>-{x64,arm64}.msi
# Reads Version from internal/buildinfo so MajorUpgrade semantics line up
# with whatever the binary reports as `--version`.
build-msi-amd64: build-windows build-windows-task
	mkdir -p dist
	@wix extension list --global 2>/dev/null | grep -q "WixToolset.Util.wixext" || \
		wix extension add --global WixToolset.Util.wixext/4.0.5
	wix build packaging/windows/Product.wxs \
		-arch x64 \
		-ext WixToolset.Util.wixext \
		-d Arch=x64 \
		-d Version=$(VERSION) \
		-d BinaryPath=$(CURDIR)/$(BINARY).exe \
		-d LauncherPath=$(CURDIR)/$(BINARY)-task.exe \
		-out dist/stepsecurity-dev-machine-guard-$(VERSION)-x64.msi

build-msi-arm64: build-windows-arm64 build-windows-task-arm64
	mkdir -p dist
	@wix extension list --global 2>/dev/null | grep -q "WixToolset.Util.wixext" || \
		wix extension add --global WixToolset.Util.wixext/4.0.5
	wix build packaging/windows/Product.wxs \
		-arch arm64 \
		-ext WixToolset.Util.wixext \
		-d Arch=arm64 \
		-d Version=$(VERSION) \
		-d BinaryPath=$(CURDIR)/$(BINARY)-arm64.exe \
		-d LauncherPath=$(CURDIR)/$(BINARY)-task-arm64.exe \
		-out dist/stepsecurity-dev-machine-guard-$(VERSION)-arm64.msi

deploy-windows:
	@bash scripts/deploy-windows.sh $(DEPLOY_ARGS)

test:
	go test ./... -v -race -count=1

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY) $(BINARY).exe $(BINARY)-task.exe $(BINARY)-arm64.exe $(BINARY)-task-arm64.exe $(BINARY)-linux
	rm -rf dist/

smoke: build
	bash tests/test_smoke_go.sh
