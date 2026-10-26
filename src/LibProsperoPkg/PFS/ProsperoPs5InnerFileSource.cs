// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
#nullable enable
using System;
using System.Collections.Generic;
using System.IO;

namespace LibProsperoPkg.PFS;

/// <summary>A file's metadata and a reader factory, without retaining its payload in memory.</summary>
public sealed class ProsperoPs5InnerFileSource
{
    /// <summary>Path relative to the inner filesystem root.</summary>
    public required string Path { get; init; }
    /// <summary>Declared logical length; the reader must supply exactly this many bytes.</summary>
    public required long Length { get; init; }
    /// <summary>Creates a readable stream. The assembler opens it once and disposes it.</summary>
    public required Func<Stream> OpenRead { get; init; }
    /// <summary>Optional override for classification from the first 20 bytes.</summary>
    public ProsperoInnerFilePolicy? Policy { get; init; }
}

/// <summary>A payload block's geometry; does not retain the compressed or uncompressed bytes.</summary>
public readonly struct ProsperoInnerPayloadBlock
{
    public long OnDiskOffset { get; init; }
    public long LogicalOffset { get; init; }
    public int CompressedSize { get; init; }
    public int UncompressedSize { get; init; }
    /// <summary>The PFSC boundary flag byte (both Kraken sub-chunks).</summary>
    public byte Flags { get; init; }
    /// <summary>First sub-chunk byte count minus one, as recorded by the PFSC encoder.</summary>
    public int SizeHint { get; init; }
    /// <summary>SHA3-256 of precisely the emitted bytes for this record (not the source bytes).</summary>
    public ReadOnlyMemory<byte> OnDiskDigest { get; init; }
    public bool IsStored => CompressedSize == UncompressedSize;
    public bool IsMultiChunk => !IsStored && UncompressedSize > 0x20000;
    public int FirstChunkCompressedSize => SizeHint + 1;
}

/// <summary>Length and block geometry of a streamed inner-image file.</summary>
public sealed class ProsperoInnerPayloadResult
{
    public required long Length { get; init; }
    public required IReadOnlyList<ProsperoInnerPayloadBlock> Blocks { get; init; }
}
