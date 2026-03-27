.PHONY: build test run validate clean

BIN := bulwark
CONFIG ?= testdata/bulwark.yaml

build:
	go build -o $(BIN) ./cmd/bulwark

test:
	go test ./... -count=1

test-verbose:
	go test ./... -v -count=1

run: build
	./$(BIN) serve --config $(CONFIG)

validate: build
	./$(BIN) validate --config $(CONFIG)

clean:
	rm -f $(BIN)
