.PHONY: test build check all

all: test

test:
	./test.sh

build:
	cd ../uplc-guest && cargo build
	cd ../onchain && cargo build
	cd ../tools/artifact-gen && cargo build
	cd ../e2e-examples && cargo build

check:
	cd ../uplc-guest && cargo check
	cd ../onchain && cargo check
	cd ../tools/artifact-gen && cargo check
	cd ../e2e-examples && cargo check

riscv:
	cd ../uplc-guest && cargo build --no-default-features --target riscv32im-unknown-none-elf
