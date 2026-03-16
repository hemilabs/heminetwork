# TSS Reference Implementations

## v3 Round Function API (current)

`v3_reference_test.go` demonstrates the tss-lib v3 pure round function
API for ECDSA distributed key generation and threshold signing.

Each round is an explicit function call: takes state + inbound messages,
returns outbound messages.  No channels, no goroutines, no recursive
state machine.  The caller owns the event loop.

```
go test -tags tssexamples -run TestV3KeygenAndSign -v -timeout 10m
```

## v2 Channel API (archived)

`testdata/v2_channel_reference/` contains the original channel-based
API examples using `NewLocalParty` / `party.Start()` / `outCh` / `endCh`.

**These files do not compile against tss-lib/v3.**  The v2 channel API
was deleted in the v3 module.  They are preserved as documentation only.
