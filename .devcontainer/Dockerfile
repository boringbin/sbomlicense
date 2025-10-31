# See https://mcr.microsoft.com/v2/devcontainers/go/tags/list
ARG VARIANT="1.25"
FROM mcr.microsoft.com/vscode/devcontainers/go:1-${VARIANT}

# Install the following external dependencies:
# 
# - [Golangci-lint](https://github.com/golangci/golangci-lint)

# Install Golangci-lint
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $(go env GOPATH)/bin v2.5.0
