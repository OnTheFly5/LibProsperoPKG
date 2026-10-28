# NativeAOT streaming regressions

This executable links the same streaming/NAPS/outer-image regression sources used by the
managed suite. It exercises the new APIs directly under NativeAOT, including
codec payloads, deferred patches, metadata layouts and readers, and encrypted
outer images with unknown-length producers and signed indirect pointers,
metadata-only FIH/SI, bounded finalized-mount SHA3/CRC generation, and complete
prepared-folder-to-local output, including CNT sealing, source overlays and
non-overwriting .part publication. Local file identity checks use platform APIs;
the workflow covers Windows x64, Linux x64 and macOS arm64. It excludes the
managed suite's legacy XML serialization reference, which intentionally uses
dynamic serialization as a comparison baseline.

For macOS Apple Silicon:

```sh
dotnet publish tests/LibProsperoPkg.StreamingNativeTests -c Release -r osx-arm64 \
  --artifacts-path /tmp/prospero-streaming-native -o /tmp/prospero-streaming-executable
/tmp/prospero-streaming-executable/LibProsperoPkg.StreamingNativeTests
```

Use the appropriate RID on other platforms. With the Homebrew .NET SDK, native
linking may additionally require `LIBRARY_PATH` pointing to its OpenSSL and
Brotli library directories. These local SDK dependencies are not a distribution
packaging solution.

The `Library regressions` workflow runs managed and native streaming suites on
Linux x64 and macOS arm64 for pushes and pull requests. The separate native
SHA3 suite remains responsible for its independent hash vectors.
