// LibProsperoPkg - A library for building and inspecting PS5 packages.
// Copyright (C) 2026 SvenGDK
#nullable enable
using System;

namespace LibProsperoPkg.PFS.Compression;

/// <summary>Final geometry and prefix patch for a sequentially written PFSC container.</summary>
public sealed class ProsperoPfscDeferredWrite
{
    /// <summary>Total container length, including reserved metadata and payload.</summary>
    public required long Length { get; init; }
    /// <summary>
    /// Replace the reserved zero prefix with these bytes after the sequential write completes.
    /// The caller owns the bytes and the destination's lifetime. A failed write returns no patch.
    /// </summary>
    public required ReadOnlyMemory<byte> Prefix { get; init; }
}
