.PHONY: all check lint doccheck vuln test race cover bench bench-smoke fuzz site-serve bump release

all: lint test

# Everything CI checks, except the long fuzz runs: make check
check: lint doccheck vuln race cover bench-smoke

lint:
	go vet ./...
	cd grpccreds && go vet ./...
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)
	golangci-lint run ./...
	cd grpccreds && golangci-lint run ./...

doccheck:
	go run ./tools/doccheck ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
	cd grpccreds && go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

test:
	go test ./...
	cd grpccreds && go test ./...

race:
	go test -race -shuffle=on ./...
	cd grpccreds && go test -race -shuffle=on ./...

# Coverage of hand-written code (example programs excluded); fails below 90%.
cover:
	go test -coverpkg=./... -coverprofile=cover.out ./... > /dev/null
	@{ head -1 cover.out; grep -v '^mode:' cover.out | grep -v '/examples/'; } > cover-hand.out
	@go tool cover -func=cover-hand.out | awk '/^total:/ {sub("%","",$$3); print "keyload: " $$3 "%"; if ($$3+0 < 90) exit 1}'
	cd grpccreds && go test -coverprofile=cover.out ./... > /dev/null
	@cd grpccreds && go tool cover -func=cover.out | awk '/^total:/ {sub("%","",$$3); print "grpccreds: " $$3 "%"; if ($$3+0 < 90) exit 1}'

bench:
	go test -run '^$$' -bench . -benchmem -count 6 .

bench-smoke:
	go test -run '^$$' -bench . -benchtime 1x ./...

# Fuzz every target: make fuzz FUZZTIME=1m
FUZZTIME ?= 30s
fuzz:
	@for t in $$(go test -list '^Fuzz' . | grep '^Fuzz'); do \
		echo "$$t"; go test -run '^$$' -fuzz "^$$t\$$" -fuzztime $(FUZZTIME) . || exit 1; \
	done

site-serve:
	@echo "http://localhost:8000"
	cd site && python3 -m http.server 8000

# Point grpccreds at the keyload version being released: make bump VERSION=v0.2.0
bump:
	@test -n "$(VERSION)" || (echo "usage: make bump VERSION=vX.Y.Z"; exit 1)
	cd grpccreds && go mod edit -require=github.com/rossedman/keyload@$(VERSION)

# Tag a release and push the tags, which starts the Release workflow:
# make release VERSION=v0.2.0
release:
	@./scripts/release.sh "$(VERSION)"
