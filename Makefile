# Makefile

.PHONY: build test smoke clean

# build
build:
	go build -o mcptrust ./cmd/mcptrust

# tests
test:
	go test ./...

# integration
gauntlet:
	bash tests/gauntlet.sh

# smoke (Ed25519)
smoke: build
	MCPTRUST_BIN=./mcptrust bash scripts/smoke.sh

# clean
clean:
	rm -f mcptrust
	rm -rf bin/
