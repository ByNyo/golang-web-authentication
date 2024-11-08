BUILD_DIR=./bin/builds
NAME=gauth

run:
	go run main.go

build: clean
	@mkdir $(BUILD_DIR)
	GOARCH=amd64 go build -o $(BUILD_DIR)/$(NAME)

run-build:
	$(BUILD_DIR)/$(NAME)

clean:
	@rm -rf $(BUILD_DIR)