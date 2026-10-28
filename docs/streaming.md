# Experimental streaming primitives

These APIs support the OnTheFly5 streaming feasibility work. They include an experimental prepared-folder-to-local FPKG path; they do not
replace the legacy `ProsperoPackageBuilder.Build` or integrate the desktop UI.

## Complete local prepared-folder path

`ProsperoPkgBuilder.BuildLocalStreaming` produces a complete experimental local
FIH/PFS/CNT/SI package from a prepared folder. It creates only the selected
`.part`, writes nested images through forward-only buffers, finalizes CNT/FIH,
reads that same patched mount once for SHA3/CRC, appends SI, validates the parsed
package and publishes without overwrite. No extracted tree or intermediate
image/package copy is written. `ProsperoStreamingPackageOptions.UseKraken`
defaults to true; false stores payloads and filesystem metadata. This is separate
from the legacy `ProsperoPackageBuilder.Build` entry point.

```csharp
var result = ProsperoPkgBuilder.BuildLocalStreaming(new ProsperoStreamingPackageOptions
{
    SourceFolder = source,
    OutputPath = target,
}, confirmDeleteExistingPart: path => userConfirmedDeletion);
```

Final output must be outside the source, in an existing directory. Existing
finals fail, including publication races. Existing partials require explicit
deletion consent; failure/cancellation removes this invocation's partial and
reports cleanup failures. Identity guards preserve detected path replacement;
portable conditional unlink/rename cannot protect against an uncooperative
writer changing the output directory continuously.

The folder catalog filters CNT/project files and injects missing keystone/about
metadata in RAM. Small UCP repair is capped at 16 MiB/file and 64 MiB overlays.
CNT inputs are frozen before payload generation (64 MiB total, 4 MiB param.json),
with no late filesystem fallback. Source files/timestamps remain unchanged.
Raw ELF conversion is not supplied: executables must already be prepared SELF.
The profile requires ASCII names, rejects links/collisions, and omits empty
directories like the existing file-only assembler. Application inputs require
eboot.bin; output within the source, including resolved directory aliases, fails.

The existing SI format still limits aligned physical inner size to its 32-bit
phdr field and file extents to 32-bit sizes. This path does not establish large
game or target-console compatibility. FTP/RAR and the production callback/UI
integration remain future work. Complete managed/NativeAOT regressions recover
all fixture payloads, validate CNT seals/digests and SI CRCs, preserve source
snapshots, exercise Kraken on/off and inject failures/cancellation/races.

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

## Data-first encrypted outer image

`ProsperoOuterPfsBuilder.WriteForPackage` accepts an append-only destination,
ordered `ProsperoOuterFileProducer` callbacks, fixed build parameters and EKPFS.
Each callback writes one file synchronously; it need not know its compressed
length in advance. Return the optional logical `SizeCompressed` inode value,
or null to use the actual bytes written. Callbacks receive a forward-only
stream, cannot seek or query its position, and must not retain it.

The inner assembler can write directly to the first producer's stream. Retain
its returned layout, then generate NAPS inside the second producer. This chain
reads each inner source once and does not allocate the entire inner or outer
image. It is covered by a byte-for-byte comparison with the buffered builders.

The outer writer pads each file's last block (an empty file still owns one
block), hashes the 64 KiB plaintext, and applies AES-XTS with the absolute
image-relative sector index. Signed files and all structural metadata use
bit 47 in the tweak; the superblock remains plaintext. Timestamps and seed are
snapshotted before callbacks run. The destination may already contain a prefix.

After payloads, it builds signed pointer blocks, inode table, directories, FLT
and superblock. Direct, single and double-indirect addressing are supported:
12 + 1,820 + 1,820² data blocks, or about 202 GiB per outer file. Higher levels
are rejected explicitly. The legacy array builder is unchanged and retains
its old limits. Supporting the mission's 400 GiB upper range needs additional
addressing validation and implementation.

`ProsperoOuterPfsStreamResult` contains sizes, block locations, superblock ICV
and `GetBlockDigest(index)`, covering final plaintext blocks. Digest storage
uses fixed-size pages (32 bytes per outer block, plus page slack), avoiding
per-digest objects and a duplicate contiguous table. Payload buffering uses
64 KiB; inode and directory sectors, pointer-node descriptors and digest pages
are additional metadata memory. No image-tree XML or full FPKG is produced.

A callback or output error aborts generation. A callback cannot suppress an
output exception and turn a failed transfer into success: the sink retains
and rethrows the failure, without retrying an encrypted block. Cancellation
propagates, and the caller owns destination cleanup and `.part` publication.

## Finalized FIH and SI without image arrays

`ProsperoFihBuilder.BuildDebugHeader(ProsperoFihHeaderMetadata)` writes the
64 KiB FIH block from explicit physical/logical geometry and SHA3-256 digests.
Use the outer result's `GetBlockDigest(SuperblockIndex)`, **not** its ICV, as the
superblock digest. Use SHA3-256 of the exact NAPS file for 0xB0. The physical
inner allocation at 0x90 comes from that file's block count, so multi-block NAPS
cannot inflate it. Logical Ndblock (0xA0) and metadata base (0x50) remain distinct.
The older array entry point retains its existing behavior.

`ProsperoFinalizedMountDigests.Compute` reads exactly the specified finalized
FIH+encrypted PFS+CNT range, excluding SI, from the source's current cursor.
It uses a 64 KiB read buffer and returns whole-mount SHA3, an optional explicit
superblock hash and PlayGo CRC-32C (one little-endian word per block, including
a partial tail without padding). It leaves the source open and never seeks.
Callers must finish/flush patches and position a local `.part` reader before
calling. Optional capture of final on-disk block hashes serves the legacy
identity-map SI profile; the nwonly path needs no duplicate block-hash table.

For FTP, the accepted design extends the supported server with a SITE hash
command after mount patches, then appends SI using APPE. That transport command
is future work. `ProsperoFinalizedMountDigests` also accepts externally computed
SHA3/root/CRC metadata; its constructor checks shape, not whether a remote
implementation hashed the correct range. Source replay is not required by this
chosen destination-readback design.

`ProsperoNapsMeta.BuildMeta18FromDigests` consumes finalized digests, captured
whole-file encoded digests and the retained inner layout. The shared payload
encoder now collects each complete encoded-file SHA3 during the first source
pass; alignment padding is excluded. Compressed metadata bytes remain retained
and supply their existing SI range digests. No source payload is reopened.

`ProsperoSiArchive.BuildDebugSiSegmentFromDigests` builds the complete SI ZIP
from those inputs and `ProsperoPfsImageXmlOptions.NestedInnerLayout`, including
XML and CRC members. The older NestedInner result API is preserved. Old array
SI generation also accepts NestedInnerLayout and routes through the new path.

The current SI caller uses aligned **physical** inner OutputLength for phdr and
meta300, whereas FIH 0xA0 uses logical Ndblock times 64 KiB. The new API preserves
that actual convention and rejects inconsistent geometry, missing digests,
out-of-range extents and unsupported 32-bit phdr/file-size fields. It preserves
the legacy coarse per-file SI projection; large-game SI mapping/widths still
need format work. A 400 GiB header-only fixture proves scalar serialization,
not complete-package support at that size. The new local entry point connects CNT construction, overlays and output lifecycle;
the legacy entry point and production desktop bindings remain separate.

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
- Higher-level outer addressing, large-game SI geometry, raw module conversion,
  FTP/RAR and production NativeAOT callback bindings remain open. No console or
  100–400 GB package claim follows from these fixtures.

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

The SI primitive now consumes captured extent hashes and finalized-mount digests.
Production integration remains separate from NAPS generation.

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
have explicit failure regressions. Finalization tests compare the entire SI ZIP
and FIH bytes with buffered output and pinned bc961cf golden hashes; distinguish
physical SI size from logical FIH size; reject inconsistent geometry/widths;
and check exact-range SHA3 and CRCs over short-reading inputs and partial tails.
Outer tests independently walk signed
single/double pointers, decrypt sampled absolute sectors, check failure
propagation and callback ownership, and check live-memory growth while writing
a synthetic 115 MiB image to a sampling sink. Console compatibility remains unverified.


The dedicated `tests/LibProsperoPkg.StreamingNativeTests` project links the same
streaming regressions for NativeAOT, excluding the managed-only legacy XML
comparison. See its README for publish/run commands. The managed suite passed
15,992 assertions and the native streaming runner passed 15,698 on macOS arm64.
The existing C ABI compatibility proof and independent 5,201 native SHA3 checks
also passed. Linux and remote workflow results must be checked independently.


## Transport-neutral prepared-folder output

`ProsperoPkgBuilder.WriteStreaming(options, output)` accepts
`IProsperoStreamingPackageOutput`, with synchronous append, flush, positional patch
and finalized-mount integrity operations. Append calls carry at most 64 KiB;
patches carry at most 1024 bytes. The writer does not read or seek its output,
create a local destination, dispose the caller's sink, or publish a package.
`OutputPath` is only a result label in this API. The caller owns exclusive output
creation, source/output separation, cleanup, transport validation and publication.

The exact order is mount append, flush, FIH patches, flush, finalized integrity,
SI append, flush. A returned summary means generation finished. A transport must
not report publication until its own completion checks and no-replace operation
succeed. Sink operations must consume borrowed buffers before returning and throw
on incomplete writes or failed commands. Cooperative cancellation is checked at
bounded writes/patches and before SI; blocked transport operations also need their
own cancellation/timeouts.

`FinalizeMount` must return SHA3-256 of the final mount, the final superblock digest
and CRC-32C records for its 64 KiB chunks, including a partial tail. A future FTP
sink can combine server-side SHA3 with locally captured CRCs corrected for patches;
that accumulator and the FTP adapter are not implemented here. The writer checks
length and the expected superblock digest before appending SI; it cannot establish
the provenance of external metadata. Do not emulate a readable/seekable mount by
buffering or downloading the complete package.

`BuildLocalStreaming` uses the same generator through a local adapter and retains
its bounded readback, structural validation, exclusive partial ownership,
non-overwriting publication and cleanup. Its source snapshots still precede
output creation. Tests compare deterministic FIH/PFS bytes between local and
callback outputs and recover the original file contents. CNT IMAGE_KEY RSA padding
is intentionally random between builds, so each CNT and SI is verified against
its own final mount rather than requiring whole-package byte equality. Tests also
cover write/flush/patch/hash failures, malformed integrity metadata and cancellation
before SI. The small callback fixtures use a memory-backed sink only for assertions.
The callback API is not yet bound to a production C ABI or FTP/RAR transport.
