.PHONY: all lint test race cover bench fuzz site-serve bump

all: lint test

lint:
	go vet ./...
	cd grpccreds && go vet ./...
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

test:
	go test ./...
	cd grpccreds && go test ./...

race:
	go test -race -shuffle=on ./...
	cd grpccreds && go test -race -shuffle=on ./...

cover:
	go test -coverpkg=./... -coverprofile=cover.out ./... > /dev/null
	go tool cover -func=cover.out | tail -1

# Benchmarks: make bench > new.txt; benchstat old.txt new.txt
bench:
	go test -run '^$$' -bench . -benchmem -count 6 .

fuzz:
	go test -run '^$$' -fuzz FuzzParseMaterial -fuzztime 1m .

site-serve:
	@echo "http://localhost:8000"
	cd site && python3 -m http.server 8000

# Point grpccreds at the keyload version being released: make bump VERSION=v0.2.0
bump:
	@test -n "$(VERSION)" || (echo "usage: make bump VERSION=vX.Y.Z"; exit 1)
	cd grpccreds && go mod edit -require=github.com/rossedman/keyload@$(VERSION)
