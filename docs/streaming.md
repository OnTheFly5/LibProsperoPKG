# Experimental streaming primitives

These APIs support the OnTheFly5 streaming feasibility work. They are not yet
an end-to-end FPKG builder and do not replace `ProsperoPackageBuilder.Build`.

## Data-first inner image

`ProsperoPs5InnerImageAssembler.Write` accepts a writable `Stream` and
`ProsperoPs5InnerFileSource` descriptors. Each descriptor provides a path,
logical length, reader factory, and optional storage-policy override. The
assembler opens each reader once in afid order, consumes the declared length,
checks for extra data, and disposes that reader. A reader need not implement
seeking, length, or position. The output remains owned by the caller and is
never read, queried for its position, or sought.

The writer classifies the leading 20 bytes without reopening the source,
streams Kraken or verbatim file payloads, then writes block-info and compressed
filesystem metadata. `ProsperoPs5InnerImageLayout` returns the final output
length, nodes, placements, metadata, and per-file compression-block records.
Offsets are relative to the start of this image; payload-block offsets are
relative to the start of their file. The older `Build` APIs still return an
in-memory `Image` for compatibility.

For example, a prepared inner-image input can contain a single asset:

```csharp
var input = new ProsperoPs5InnerFileSource
{
    Path = "/asset.bin",
    Length = new FileInfo(sourcePath).Length,
    OpenRead = () => File.OpenRead(sourcePath),
};
var assembler = new ProsperoPs5InnerImageAssembler(buildTimeSeconds, 0);
ProsperoPs5InnerImageLayout layout = assembler.Write(output, [input], cancellationToken);
```

The caller must select the inner file set and handle outer-CNT metadata and
module conversion; this method is not a general folder-to-package entry point.
Neither source files nor the destination are implicitly created or renamed.

`ProsperoPs5InnerImageBuilder.WritePayload` is the lower-level primitive. It
writes concatenated PFSC payload blocks, without a PFSC container prefix, and
returns their logical/physical sizes, flags, subchunk hints, and SHA3-256 digests
of the emitted bytes. These digests cover each returned record; consumers must
still map them to the exact integrity ranges required by NAPS/SI. It shares the
encoder and compressed-versus-stored decision with the standalone PFSC writer.
This matches the representation used by the current nwonly inner image.

## Standalone PFSC with a deferred prefix

`ProsperoCompressedPfsFileWriter.WriteDeferred` writes a real zero-filled
metadata reservation followed by the payload to a write-only, append-only
stream. It returns `ProsperoPfscDeferredWrite.Length` and `.Prefix`.

After the sequential transfer has finished, overwrite the reservation with the
returned prefix. The patch begins at the container's original starting offset,
which the caller must track; it is not necessarily offset zero of the entire
output. A transport can split the prefix into 1024-byte PWRITE requests. All
patch bytes belong to an already-emitted range and must preserve the payload.
No output readback or recompression is needed to construct this prefix.

The unfinished container must not be treated as valid until patching succeeds.
Do not confuse this standalone PFSC facility with complete FPKG finalization:
the current package path stores raw compression payloads and has additional
layout, integrity and signing dependencies.

## Ownership, resources, and limitations

- Payload buffering is bounded by codec block/workspace size. The raw payload
  writer uses one 256 KiB input buffer; block geometry and filesystem metadata
  remain proportional to block/file counts. This is not a bound on total RSS.
- Sources must remain stable during generation. A length change is rejected;
  an equal-length content change cannot be detected from length checks alone.
- Output failures and cancellation propagate to the caller. Output may be
  incomplete; the caller owns cleanup. These methods do not manage `.part`
  publication or retry policy.
- Inodes are packed into complete 64 KiB sectors (390 entries per sector).
  Auxiliary tables and directories reserve as many sectors as needed. Entries
  never cross directory-sector boundaries, and parent offsets include padding.
- Metadata's logical base moves beyond the logical data end when high
  compression would make the original physical-length-based address overlap.
  This changes formerly invalid layouts while preserving the small golden fixture.
- The current name codec is ASCII. Streaming source descriptors reject
  unsupported Unicode names and unrepresentable 40-bit sizes/offsets before
  opening payload readers rather than silently renaming/truncating them.
- Outer filesystem addressing, SI generation, source overlays, full-package
  hashing, no-Kraken package mode, and NativeAOT callback bindings remain to be
  integrated. No console or 100–400 GB package claim follows from these fixtures.

## NAPS and metadata inspection

`ProsperoNwonlyNapsGenerator.Generate(ProsperoPs5InnerImageLayout)` builds NAPS
using the captured records and `OutputLength`, without reading the inner image.
Both buffered and streamed assemblers now retain real codec block records.
Mixed compressed/stored files and metadata are modeled per block; empty files
retain their catalog entries without zero-length data records. Invalid block
coverage, subchunk sizes, or packed field widths fail explicitly.

The u2c builder uses the documented 24-bit base and seven delta bytes. The
extra sentinel group for exact multiples of eight is handled explicitly.
Byte-sized deltas still limit unusually dense block plans. The existing
successor lookup policy is retained; its native lookup behavior requires
reference/console validation. The inspection reader does not use u2c, so tests
check serialized lookup entries separately from payload reconstruction.

`ProsperoPs5InnerImageReader.ReadFileTreeFromMetadata` walks only retained
metadata and returns full logical offsets, including offsets above 400 GiB,
without allocating a mount. `ReconstructMount` remains a small-image inspection
API; it now handles compressed cursor wrap, logical metadata placement, and
multi-sector inodes, and rejects incomplete or malformed block plans.

Neither API yet eliminates the SI builder's whole-image dependency. Source
replay and whole-package integrity work remain separate from NAPS generation.

## Regression checks

Run the existing owning suite:

```sh
dotnet run --project tests/LibProsperoPkg.Tests/LibProsperoPkg.Tests.csproj \
  --artifacts-path /tmp/libprospero-streaming-tests
```

Streaming tests compare encoded payloads and patched PFSC containers against
legacy output; compare a streamed inner image with both the array builder and
an independently generated hash from pinned revision `db8510e`; exercise
nonseekable short-reading sources and write-only outputs; check unchanged
folder inputs, source shrink/growth, cancellation, write errors, bounded
read/write sizes, and synthetic-input allocation growth. NAPS regressions recover
every file byte across mixed blocks, cursor wraps, long raw runs, and highly
compressed input; check serialized lookup bases beyond 255 and sentinel groups;
and walk 5,000-file/multi-sector metadata. Malformed metadata and field truncation
have explicit failure regressions. Console compatibility remains unverified.


The dedicated `tests/LibProsperoPkg.StreamingNativeTests` project links the same
streaming regressions for NativeAOT, excluding the managed-only legacy XML
comparison. See its README for publish/run commands. The managed suite passed
6,250 assertions and the native streaming runner passed 5,960 on macOS arm64.
The existing C ABI compatibility proof and independent 5,201 native SHA3 checks
also passed. Linux and remote workflow results must be checked independently.
