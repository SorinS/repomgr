# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOLINT=bin/golangci-lint run
BINARY_NAME=repomgr

DATE=$(shell date +%Y%m%d_%H%M%S)
VERSION=0.1.0
COMMIT=$(shell git rev-parse HEAD)
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(DATE)"

# Compilation targets
#all: macosx-arm64 linux-amd64 windows-amd64
all: macosx

macosx:
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o build/$(BINARY_NAME)-macosx-arm64.bin

linux:
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o build/$(BINARY_NAME)-linux-amd64.bin

windows:
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o build/$(BINARY_NAME)-windows-amd64.exe

# Testing and linting targets
test:
	$(GOTEST) -v ./...

lint:
	$(GOLINT) ./...

clean:
	$(GOCLEAN)
	rm -rf build/

