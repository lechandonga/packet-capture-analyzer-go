.PHONY: test test-race test-verbose build fmt vet

# All tests are offline: captures are synthesized in memory by
# internal/pcapgen; no network interface or external service is used.
test:
	go test ./...

test-verbose:
	go test -v ./...

test-race:
	CGO_ENABLED=1 go test -race ./...

build:
	go build ./...

fmt:
	gofmt -w .

vet:
	go vet ./...
