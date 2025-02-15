PROJ_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
PROJ_DIR := $(subst \,/,$(PROJ_DIR))
BIN_DIR ?= $(PROJ_DIR)build/

export CGO_LDFLAGS := -L$(BIN_DIR)
export CGO_CFLAGS := -I$(PROJ_DIR)build/
export GOOS
export GOARCH
export GOARM
export BIN_DIR

CGO_TEST_LDFLAGS = $(CGO_LDFLAGS) -Wl,-rpath,$(BIN_DIR)

ifeq ($(OS),Windows_NT)
	HOST_OS := windows
else
	HOST_OS := $(shell uname | tr [A-Z] [a-z])
endif

ifeq ($(GOOS),)
	GOOS := $(HOST_OS)
endif

ifeq ($(GOARCH),)
	GOARCH := $(shell go env GOARCH)
endif

ifeq ($(GOOS),windows)
	platform := windows
	export PATH := $(PATH):$(PROJ_DIR)build
	EXE := .exe
else
	TEMP := /tmp
	ifeq ($(GOOS),darwin)
		ifeq ($(GOARCH),arm64)
				platform := macos-m1
		else
				platform := macos
		endif
		CGO_LDFLAGS := $(CGO_LDFLAGS) -Wl,-rpath,@loader_path
		ULIMIT := ulimit -n 9999;
	else
		ifeq ($(GOARCH),arm64)
				platform := linux-arm64
		else
				platform := linux
		endif
		CGO_LDFLAGS := $(CGO_LDFLAGS) -Wl,-rpath,$$ORIGIN
	endif
endif

POSTRS_SETUP_REV = 0.4.0
POSTRS_SETUP_ZIP = libpost-$(platform)-v$(POSTRS_SETUP_REV).zip
POSTRS_SETUP_URL_ZIP ?= https://github.com/spacemeshos/post-rs/releases/download/v$(POSTRS_SETUP_REV)/$(POSTRS_SETUP_ZIP)
ifeq ($(platform), windows)
	POSTRS_SETUP_LIBS = post.h post.dll
else
	ifeq ($(platform), $(filter $(platform), macos macos-m1))
		POSTRS_SETUP_LIBS = post.h libpost.dylib
	else
		POSTRS_SETUP_LIBS = post.h libpost.so
	endif
endif

BINDIR_POSTRS_SETUP_LIBS = $(foreach X,$(POSTRS_SETUP_LIBS),$(BIN_DIR)$(X))
$(BINDIR_POSTRS_SETUP_LIBS): $(PROJ_DIR)$(POSTRS_SETUP_ZIP)
	mkdir -p $(dir $@)
	unzip -o -j $(PROJ_DIR)$(POSTRS_SETUP_ZIP) -d $(dir $@) $(notdir $@)
	touch $@

$(PROJ_DIR)$(POSTRS_SETUP_ZIP):
	curl -L $(POSTRS_SETUP_URL_ZIP) -o $(PROJ_DIR)$(POSTRS_SETUP_ZIP)

get-postrs-lib: $(PROJ_DIR)$(POSTRS_SETUP_ZIP) $(BINDIR_POSTRS_SETUP_LIBS)

go-env: get-postrs-lib
	go env -w CGO_CFLAGS="$(CGO_CFLAGS)"
	go env -w CGO_LDFLAGS="$(CGO_LDFLAGS)"
.PHONY: go-env

go-env-test: get-postrs-lib
	go env -w CGO_CFLAGS="$(CGO_CFLAGS)"
	go env -w CGO_LDFLAGS="$(CGO_TEST_LDFLAGS)"
.PHONY: go-env-test

print-env: get-postrs-lib
	@echo CGO_CFLAGS="\"$(CGO_CFLAGS)\"" CGO_LDFLAGS="\"$(CGO_LDFLAGS)\""
.PHONY: print-env

print-test-env: get-postrs-lib
	@echo CGO_CFLAGS="\"$(CGO_CFLAGS)\"" CGO_LDFLAGS="\"$(CGO_TEST_LDFLAGS)\""
.PHONY: print-test-env
