BINARY_NAME=voidscope.exe

build:
	go build -o $(BINARY_NAME) ./cmd/voidscope

clean:
	go clean
	rm -f $(BINARY_NAME)

test:
	go test ./...

run: build
	./$(BINARY_NAME)
