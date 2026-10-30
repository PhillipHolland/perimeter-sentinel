.PHONY: test vet build ci

test:
	go test ./...

vet:
	go vet ./...

build:
	mkdir -p bin
	go build -o bin/perimeterctl ./cmd/perimeterctl

ci: test vet
	bash ci/license-gate.sh
	bash ci/secret-scan.sh
