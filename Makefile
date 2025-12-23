# Makefile

.PHONY: build test smoke clean

# build binary
	go build -o mcptrust ./cmd/mcptrust

# unit tests
	go test ./...

# integration tests
	bash tests/gauntlet.sh

# smoke test
	MCPTRUST_BIN=./mcptrust bash scripts/smoke.sh

# cleanup
	rm -f mcptrust
	rm -rf bin/
