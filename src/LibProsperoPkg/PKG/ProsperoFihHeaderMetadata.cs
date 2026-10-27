// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
#nullable enable
using System;

namespace LibProsperoPkg.PKG;

/// <summary>Final geometry and hashes for the two-file nwonly debug image. No payload bytes.</summary>
public sealed class ProsperoFihHeaderMetadata
{
    public required long PfsSize { get; init; }
    public required long SuperblockIndex { get; init; }
    /// <summary>SHA3-256 of the complete plaintext outer superblock, distinct from its ICV.</summary>
    public required ReadOnlyMemory<byte> SuperblockDigest { get; init; }
    public required long InnerStoredBlockCount { get; init; }
    public required long InnerLogicalBlockCount { get; init; }
    public required long InnerMetadataBaseBlock { get; init; }
    public required long NapsLength { get; init; }
    /// <summary>SHA3-256 of exactly the NAPS file bytes, excluding outer block padding.</summary>
    public required ReadOnlyMemory<byte> NapsDigest { get; init; }
    public int InnerContentInodes { get; init; }
    public int AppFileCount { get; init; }
    public uint ContentVersionHi { get; init; }
}
