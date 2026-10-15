VERSION := $(shell git describe --tags --always 2>/dev/null || echo 0.0.0-dev)

build: version.swift
	swiftc -O -o kc kc.swift version.swift

version.swift: FORCE
	@echo 'let kcVersion = "$(VERSION)"' > $@

test: build
	bash tests/test.sh

clean:
	rm -f kc version.swift

FORCE:
.PHONY: build test clean FORCE
