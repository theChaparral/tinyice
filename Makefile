.PHONY: build run test clean

build:
	go build -o tinyice

run: build
	./tinyice

test:
	go test ./...

clean:
	rm -f tinyice
