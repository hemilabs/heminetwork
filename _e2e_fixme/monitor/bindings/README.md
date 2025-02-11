# Test Monitor Bindings

## What are they?

The "Test Monitor Bindings" are go files that are generated from solidity files.
These should never need to change, so the transpilation process has been 
omitted.  

The files themselves are meant to provide and api for deploying and interacting
with custom smart contracts in the localnet test environment.  If these need to
be change, it's best to create new ones for the new test case's need and deploy
it.

You can generate your needed files with solc+abigen.

for example

```shell
solc --bin --abi path/to/MyFile.sol -o e2e/monitor/bindings --overwrite
abigen --bin=e2e/monitor.bindings/MyFile.bin  --abi=e2e/monitor/bindings/MyFile.abi --pkg=bindings --out=MyFile.go
```