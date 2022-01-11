.PHONY:clean compile install

P4NAME="P4Zeek"
VERBOSE=3
ROOT_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))


ALL: clean build install

build:
	@echo "\033[32m make directory \033[0m"
	@mkdir -p build
	@echo "\033[32m compile start \033[0m"
	@cd build && ${ROOT_DIR}/compile_9.7.sh -p ${ROOT_DIR} -f ${P4NAME} -v ${VERBOSE}

install:
	@echo "\033[32m Install binary to SDE \033[0m"
	@cd build && make && make install

clean:
	@rm -rf build
