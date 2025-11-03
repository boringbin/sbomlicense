.PHONY: all cli daemon tidy vet lint-check lint-fix format-check format-fix check fix test test-integration test-coverage test-all clean

# all: Build both CLI and daemon binaries.
all: cli daemon

# cli: Build the CLI tool.
cli:
	go build -o bin/sbomlicense ./cmd/sbomlicense

# daemon: Build the daemon server.
daemon:
	go build -o bin/sbomlicensed ./cmd/sbomlicensed

# tidy: Run the go mod tidy command.
tidy:
	go mod tidy

# vet: Run the vet tool.
vet:
	go vet ./...

# lint-check: Check if the code is linted.
lint-check:
	golangci-lint run

# lint-fix: Fix the lint issues.
lint-fix:
	golangci-lint run --fix

# format-check: Check if the code is formatted.
format-check:
	test -z $(gofmt -l .)

# format-fix: Format the code.
format-fix:
	gofmt -w .

# check: Run both lint-check and format-check.
check: format-check lint-check

# fix: Run both format-fix and lint-fix.
fix: format-fix lint-fix

# test: Run unit tests (excludes integration tests).
test:
	go test -v -short -race ./...

# test-integration: Run integration tests.
test-integration:
	go test -v -tags=integration ./...

# test-coverage: Run tests with coverage report.
test-coverage:
	go test -v -short -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

# test-all: Run all tests including integration tests.
test-all:
	go test -v -race ./...
	go test -v -tags=integration ./...

# clean: Clean the project.
clean:
	rm -f bin/sbomlicense bin/sbomlicensed coverage.out coverage.html
