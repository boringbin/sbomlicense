# See https://mcr.microsoft.com/v2/devcontainers/go/tags/list
ARG VARIANT="1.25@sha256:8c6933760f4c5dd07ec3f2838bb5e664e7c19e6186da6e8000c60c4a278a404d"
FROM mcr.microsoft.com/devcontainers/go:${VARIANT}

# Install the following external dependencies:
# 
# - [Golangci-lint](https://github.com/golangci/golangci-lint)

# Install Golangci-lint
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $(go env GOPATH)/bin v2.5.0
