# NativeAOT SHA3 regression

Publishes a native executable which directly exercises the vendored managed SHA3-256
fallback, including on hosts that also provide native SHA3. The 520 embedded reference
vectors were generated independently with Python hashlib.sha3_256 for inputs of lengths
0 through 512, 1023, 1024, 1025, 65535, 65536, 65537 and 1048576 bytes. Byte i is
(i * 37 + 11) modulo 256. The FIPS abc vector is also checked. Buffer, stream, span,
instance reuse and six incremental chunk sizes produce 5201 checks in total.

```sh
dotnet publish tests/LibProsperoPkg.NativeTests -c Release -r osx-arm64 -o bin/NativeTests
bin/NativeTests/LibProsperoPkg.NativeTests
```

Use the native RID for Windows/Linux. The OnTheFly5 Scripts/ProbeNativeAot.py runner
also publishes and runs this project, directing all generated artifacts outside this checkout.
