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
- The current inner metadata representation reserves one 64 KiB inode block
  (390 records maximum) and one block per auxiliary table/directory. Oversized
  representations fail explicitly instead of overwriting neighboring blocks.
- The new inner writer also rejects detected overlap between logical file data
  and metadata in the current highly compressed mount geometry. Larger-layout
  support requires separate format work.
- NAPS/SI generation, outer filesystem addressing, source overlays, full-package
  hashing, no-Kraken package mode, and NativeAOT callback bindings are not
  integrated with these primitives yet. No console or 100–400 GB claim follows
  from the streaming fixtures.

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
folder inputs, capacity rejection, source shrink/growth, cancellation, write
errors, bounded read/write sizes, and synthetic-input allocation growth.
