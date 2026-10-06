.PHONY: test test-race vet build fmt

test:
	go test ./... -v

test-race:
	CGO_ENABLED=1 go test -race ./...

vet:
	go vet ./...

build:
	go build -o bin/pcap-analyze ./cmd/pcap-analyze

fmt:
	gofmt -w .
