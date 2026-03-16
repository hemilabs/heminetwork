# V2 Channel-Based Reference Implementation

These files are the original tss-lib v2 channel-based API examples,
preserved as documentation.  They demonstrate the `NewLocalParty` /
`party.Start()` / `outCh` / `endCh` / `errCh` pattern that was
replaced by the v3 pure round function API.

**These files do not compile against tss-lib/v3.**  The v2 channel
API (`tss.Party`, `BaseUpdate`, `BaseStart`, `Round` interface)
was deleted in the v3 module.

For the current API, see `../v3_reference_test.go`.
