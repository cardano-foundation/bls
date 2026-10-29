# CI for zkVM

CI configuration for testing zkVM components.

## Run locally

```bash
cd zkVM/ci
./test.sh
# or
make test
```

## Tests run
- uplc-guest unit tests and differential tests
- uplc-guest riscv32im target build check
- zkvm-onchain tests
- aiken-artifact-gen tests
- zkvm-e2e-examples tests

## Make targets
```bash
make test   # run all tests
make build  # build all zkVM crates
make check  # cargo check all crates
make riscv  # build for riscv32im target
```
