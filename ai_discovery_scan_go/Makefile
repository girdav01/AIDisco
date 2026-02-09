APP_NAME := ai_discovery_scan
BUILD_DIR := build

.PHONY: all clean build build-all build-linux build-windows build-macos

all: build

build:
	go build -o $(APP_NAME) .

build-all: build-linux build-windows build-macos

build-linux:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 .

build-windows:
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe .
	GOOS=windows GOARCH=arm64 go build -o $(BUILD_DIR)/$(APP_NAME)-windows-arm64.exe .

build-macos:
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 .

clean:
	rm -f $(APP_NAME) $(APP_NAME).exe
	rm -rf $(BUILD_DIR)
	rm -rf output/
