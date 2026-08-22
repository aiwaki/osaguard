.PHONY: build test check tray-deps tray-test tray-build

build:
	mkdir -p build
	go build -trimpath -o build/osaguard ./cmd/osaguard

test:
	go test -race ./...

check: test build
	go vet ./...
	cd app-tauri && npm test
	cd app-tauri && npm audit --audit-level=high
	cd app-tauri/src-tauri && cargo fmt --all -- --check
	cd app-tauri/src-tauri && cargo test --locked
	cd app-tauri/src-tauri && cargo clippy --locked --all-targets --all-features -- -D warnings

tray-deps:
	cd app-tauri && npm ci

tray-test:
	cd app-tauri/src-tauri && cargo test --locked

tray-build: build tray-deps
	cd app-tauri && npm run build:local
