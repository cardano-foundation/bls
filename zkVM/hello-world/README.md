# Aiken hello world (zkVM Phase 1)

Simple program computing `sha2_256("Hello, world!")` to differential-test
against OpenVM and Jolt guests.

## Expected results

Same guest output for both VMs:
`315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3`
(`SHA-256("Hello, world!")`).
