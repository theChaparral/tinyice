.PHONY: build generate dev clean

# Full build: rebuild frontend + compile Go binary
build: generate
	go build -o tinyice .

# Rebuild frontend assets via go generate
generate:
	go generate ./server/...

# Quick build: Go only (skip frontend rebuild)
quick:
	go build -o tinyice .

# Dev: run frontend dev server
dev:
	cd server/frontend && npm run dev

clean:
	rm -f tinyice
	rm -rf server/frontend/dist
