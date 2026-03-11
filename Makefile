APP_NAME := boce_dns_checker
MAIN_PKG := ./cmd/boce_dns_checker
BUILD_DIR := ./build

.PHONY: all clean darwin-arm64 linux-amd64

all: darwin-arm64 linux-amd64

darwin-arm64:
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(APP_NAME)_darwin_arm64 $(MAIN_PKG)

linux-amd64:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(APP_NAME)_linux_amd64 $(MAIN_PKG)

clean:
	rm -rf $(BUILD_DIR)
