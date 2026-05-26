VERSION   ?= $(shell git describe --tags --always)
BUILDTIME ?= $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
CODENAME  ?= unknown
BINARY    := crawlofduty
BUILD_DIR  := dist
MAIN_PACKAGE = main
LDFLAGS := -s -w -buildid= \
	-X $(MAIN_PACKAGE).version=$(VERSION) \
	-X $(MAIN_PACKAGE).codename=$(CODENAME) \
	-X $(MAIN_PACKAGE).buildTime=$(BUILDTIME)

.PHONY: build release

build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(BINARY) $(MAIN)

release-linux-amd64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(BINARY)-linux-amd64 $(MAIN)

release-linux-arm64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(BINARY)-linux-arm64 $(MAIN)

release-windows-amd64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe $(MAIN)

release-darwin-arm64:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 $(MAIN)

release-all: release-linux-amd64 release-linux-arm64 release-windows-amd64 release-darwin-arm64
